import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class SmmCalloutHunter_v3 extends GhidraScript {
    // 디컴파일러
    private DecompInterface decomp;
    // 이미 방문한 함수 주소를 저장하여 무한 루프 방지
    private Set<Address> visitedFunctions = new HashSet<>();

    // Def-Use Chain에서 찾은 gBS 주소를 저장할 변수
    private Address foundGbsAddr = null;

    @Override
    protected void run() throws Exception {
        println("==================================================");
        println("Starting SMM Callout using gBS...v4.0 (Root & Child)");
        println("==================================================");

        // ==================================================
        // [Phase 0-1] 이 파일이 SMM 드라이버가 맞는지 감별
        // ==================================================
        if (!isSmmDriver()) {
            println("[-] Could not find SMM_BASE2_PROTOCOL");
            println("[-] 일반 DXE 드라이버이므로 종료.");
            saveJsonToFileIfError("SMM 드라이버가 아니어서 조기 종료됨.");
            return;
        }

        println("[+] SMM 드라이버 확인 완료. 본격적인 분석 시작.🕵️‍♂️");

        // 디컴파일러 초기화
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // ==================================================
        // [Phase 0-2] find Handlers: 숨어있는 Root 및 Child 핸들러 찾아내기
        // ==================================================
        List<Address> smiHandlers = new ArrayList<>();

        println("\n[1] Root 핸들러 탐색 시작...");
        smiHandlers.addAll(findAndCreateSmiHandlers()); // 기존 로직 (gSmst + 0xE0)

        println("\n[2] Child 핸들러 탐색 시작...");
        smiHandlers.addAll(findChildSmiHandlers());     // 신규 로직 (SW_DISPATCH + 0x0)

        if (smiHandlers.isEmpty()) {
            println("[-] 등록된 SMI 핸들러를 하나도 찾지 못했습니다. 스크립트 종료.");
            saveJsonToFileIfError("SMI 핸들러를 찾지 못함.");
            return;
        }

        println("==================================================");
        println("[+] 탐색 및 생성 완료! 총 " + smiHandlers.size() + "개의 핸들러 확보.");


        // ==================================================
        // [Phase 1] Def-Use: gBS 전역 변수 위치 찾기
        // ==================================================
        println("\ngBS 전역 변수 탐색 시작");

        AddressIterator entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (entryPoints.hasNext()) {
            // 보통 UEFI는 _ModuleEntryPoint이 진입점이므로, 첫 번째 엔트리 포인트를 사용
            Function entryFunc = getFunctionAt(entryPoints.next());
            // System Table 포인터는 entry 함수의 두번쨰 인자.
            Varnode systemTableNode = getParameterVarnode(entryFunc, 1);

            if (systemTableNode != null) {
                visitedFunctions.add(entryFunc.getEntryPoint());
                // SystemTable 포인터를 통해 gBS 추적
                boolean found = trackSystemTable(entryFunc, systemTableNode, 0);

                // 찾지 못했을 경우
                if (!found) {
                    println("[-] gBS 추적 실패. 스크립트를 종료합니다.");
                    saveJsonToFileIfError("gBS 전역 변수 위치를 찾지 못해 분석을 종료함.");
                    return;
                }
            } else {
                println("[-] Entry Point 파라미터 분석 실패. 스크립트를 종료합니다.");
                saveJsonToFileIfError("Entry Point의 시스템 테이블 포인터를 찾지 못해 분석을 종료함.");
                return;
            }
        } else {
            println("[-] Entry Point를 찾을 수 없습니다. 스크립트를 종료합니다.");
            saveJsonToFileIfError("Entry Point를 찾지 못해 분석을 종료함.");
            return;
        }

        println("[+] 타겟 gBS 주소: " + foundGbsAddr);
        println("--------------------------------------------------");


        // ==================================================
        // [Phase 2] Use-Def: SMM Callout 취약점 스캔
        // ==================================================
        println("SMM Callout 취약점 스캔 시작!");
        println("--------------------------------------------------");

        scanForSmmCallouts(smiHandlers);

        println("모든 분석이 완료되었습니다.");
    }

    // -------------------------------------------------------
    // [신규] Child 핸들러 (SW_DISPATCH) 탐색 로직
    // -------------------------------------------------------
    private List<Address> findChildSmiHandlers() {
        List<Address> handlers = new ArrayList<>();

        // EFI_SMM_SW_DISPATCH2_PROTOCOL GUID (1순위 타겟)
        byte[] swDispatchGuid = new byte[] {
                (byte)0xdc, (byte)0xc6, (byte)0xa3, (byte)0x18, // 0x18a3c6dc
                (byte)0xea, (byte)0x5e,                         // 0x5eea
                (byte)0xc8, (byte)0x48,                         // 0x48c8
                (byte)0xa1, (byte)0xc1, (byte)0xb5, (byte)0x33, (byte)0x89, (byte)0xf9, (byte)0x89, (byte)0x99
        };

        try {
            // 1. 메모리에서 해당 프로토콜의 GUID 찾기
            Address guidAddr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), swDispatchGuid, null, true, monitor);
            if (guidAddr == null) {
                println("  [-] SW_DISPATCH2_PROTOCOL 발견 안 됨. (해당 Child 핸들러 없음)");
                return handlers;
            }
            println("  [+] SW_DISPATCH 바코드 발견: " + guidAddr);

            // 2. 이 GUID를 사용하는 위치(XREF)를 역추적하여 함수 목록 확보
            Set<Function> refFunctions = new HashSet<>();

            // referenceIterator를 사용, while 문으로 순회합니다.
            ghidra.program.model.symbol.ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(guidAddr);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function func = getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    refFunctions.add(func);
                }
            }

            // 3. 확보된 함수 내부만 탐색 (전체 스캔 안 함 = 속도 최적화)
            for (Function func : refFunctions) {
                DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                HighFunction highFunc = results.getHighFunction();
                if (highFunc == null) continue;

                Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
                while (ops.hasNext()) {
                    PcodeOp op = ops.next();
                    // Child 등록 함수(Register)도 결국 CALLIND(간접 호출)를 사용함
                    if (op.getOpcode() == PcodeOp.CALLIND) {
                        // Protocol->Register(This, DispatchFunction, ...)
                        // 인자 0: 타겟 주소, 인자 1: This, 인자 2: 우리가 찾는 핸들러 주소
                        if (op.getNumInputs() > 2) {
                            Varnode handlerArg = op.getInput(2);

                            if (handlerArg != null && handlerArg.isConstant()) {
                                Address handlerAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(handlerArg.getOffset());

                                // 해당 주소가 유효한 메모리 공간인지 검증(가볍게)
                                if (currentProgram.getMemory().contains(handlerAddr)) {
                                    println("  [!] Child 핸들러(SW SMI) 등록 포착! (위치: " + func.getName() + ")");
                                    println("  [+] 타겟 Child 핸들러 주소: " + handlerAddr);
                                    handlers.add(handlerAddr);

                                    // 기드라에 등록
                                    Function existingFunc = getFunctionAt(handlerAddr);
                                    if (existingFunc == null) {
                                        try {
                                            disassemble(handlerAddr);
                                            createFunction(handlerAddr, "ChildSmiHandler_" + handlerAddr.toString());
                                            println("  ✨ 성공: Child 핸들러 함수 생성 완료!");
                                        } catch (Exception e) {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            println("Child 핸들러 탐색 중 오류: " + e.getMessage());
        }
        return handlers;
    }

    // (기존) 코드 전체를 순회하며 Root SMI 핸들러를 찾는 함수
    private List<Address> findAndCreateSmiHandlers() {
        List<Address> handlers = new ArrayList<>();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);

        while (funcs.hasNext()) {
            Function func = funcs.next();
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) continue;

            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() == PcodeOp.CALLIND) {
                    Varnode targetFuncPtr = op.getInput(0);

                    // 0xE0(Root Handler) 역추적
                    if (hasOffsetE0(targetFuncPtr, 0)) {
                        Varnode handlerArg = op.getInput(1); // Root는 1번 인자가 핸들러
                        if (handlerArg != null && handlerArg.isConstant()) {
                            Address handlerAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(handlerArg.getOffset());
                            handlers.add(handlerAddr);

                            println("  [!] Root 핸들러(gSmst) 등록 포착! (위치: " + func.getName() + ")");
                            println("  [+] 타겟 Root 핸들러 주소: " + handlerAddr);

                            Function existingFunc = getFunctionAt(handlerAddr);
                            if (existingFunc == null) {
                                try {
                                    disassemble(handlerAddr);
                                    createFunction(handlerAddr, "RootSmiHandler_" + handlerAddr.toString());
                                    println("  ✨ 성공: Root 핸들러 함수 생성 완료!");
                                } catch (Exception e) {}
                            }
                        }
                    }
                }
            }
        }
        return handlers;
    }

    // -------------------------------------------------------
    // [Phase 0-1 Logic] SMM 드라이버 감별 함수 (GUID 스캔)
    // -------------------------------------------------------
    private boolean isSmmDriver() {
        byte[] smmBase2Guid = new byte[] {
                (byte)0xb7, (byte)0xbf, (byte)0xcc, (byte)0xf4,
                (byte)0xe0, (byte)0xf6,
                (byte)0xfd, (byte)0x47,
                (byte)0x9d, (byte)0xd4, (byte)0x10, (byte)0xa8, (byte)0xf1, (byte)0x50, (byte)0xc1, (byte)0x91
        };

        try {
            Address foundAddr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), smmBase2Guid, null, true, monitor);
            if (foundAddr != null) {
                println("[SMM_BASE2_PROTOCOL GUID] 발견! 위치: " + foundAddr);
                return true;
            }
        } catch (Exception e) {}

        return false;
    }

    // ... (trackSystemTable, checkIfStoredToGlobal, trackValueToMemory 등 기존 Phase 1 로직 동일) ...
    private boolean trackSystemTable(Function func, Varnode node, int depth) {
        if (node == null || depth > 10) return false;
        Iterator<PcodeOp> uses = node.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.PTRADD || opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRSUB) {
                Varnode offsetNode = op.getInput(1);
                if (offsetNode != null && offsetNode.isConstant() && offsetNode.getOffset() == 0x60) {
                    println("[+0x60 Catch!] 함수: " + func.getName());
                    if (checkIfStoredToGlobal(op.getOutput(), 0)) return true;
                }
            } else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                if (trackSystemTable(func, op.getOutput(), depth)) return true;
            } else if (opcode == PcodeOp.CALL) {
                Address targetAddr = op.getInput(0).getAddress();
                Function targetFunc = getFunctionAt(targetAddr);
                if (targetFunc != null && !visitedFunctions.contains(targetAddr)) {
                    int paramIndex = -1;
                    for (int i = 1; i < op.getNumInputs(); i++) {
                        if (op.getInput(i) == node) {
                            paramIndex = i - 1;
                            break;
                        }
                    }
                    if (paramIndex != -1) {
                        visitedFunctions.add(targetAddr);
                        Varnode nextNode = getParameterVarnode(targetFunc, paramIndex);
                        if (trackSystemTable(targetFunc, nextNode, depth + 1)) return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean checkIfStoredToGlobal(Varnode ptrNode, int depth) {
        if (ptrNode == null || depth > 5) return false;
        Iterator<PcodeOp> uses = ptrNode.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.CAST || opcode == PcodeOp.COPY) {
                if (checkIfStoredToGlobal(op.getOutput(), depth + 1)) return true;
            } else if (opcode == PcodeOp.LOAD) {
                if (trackValueToMemory(op.getOutput(), 0)) return true;
            }
        }
        return false;
    }

    private boolean trackValueToMemory(Varnode node, int depth) {
        if (node == null || depth > 5) return false;
        Iterator<PcodeOp> uses = node.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.STORE) {
                Varnode destNode = op.getInput(1);
                if (destNode != null && destNode.isConstant()) {
                    foundGbsAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(destNode.getOffset());
                    println("gBS 전역 변수 발견: " + foundGbsAddr);
                    try { createLabel(foundGbsAddr, "gBS_Global_Variable", true); } catch (Exception e) {}
                    return true;
                }
            } else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.MULTIEQUAL || opcode == PcodeOp.INDIRECT) {
                Varnode destNode = op.getOutput();
                if (destNode != null) {
                    if (destNode.getAddress().isMemoryAddress()) {
                        foundGbsAddr = destNode.getAddress();
                        println("gBS 전역 변수 발견: " + foundGbsAddr);
                        try { createLabel(foundGbsAddr, "gBS_Global_Variable", true); } catch (Exception e) {}
                        return true;
                    } else {
                        if (trackValueToMemory(destNode, depth + 1)) return true;
                    }
                }
            }
        }
        return false;
    }

    // -------------------------------------------------------
    // [Phase 2 Logic] 역방향 추적 (Use-Def) - SMM Callout 탐지
    // -------------------------------------------------------
    private void scanForSmmCallouts(List<Address> smiHandlers) {
        int vulnCount = 0;
        List<String> locationsList = new ArrayList<>();
        Set<Function> runtimeFunctions = new HashSet<>();

        for (Address addr : smiHandlers) {
            Function handlerFunc = getFunctionAt(addr);
            if (handlerFunc != null) {
                buildRuntimeCallGraph(handlerFunc, runtimeFunctions);
            }
        }

        println("런타임 스캔 대상 함수 총 " + runtimeFunctions.size() + "개 추출 완료!");

        for (Function func : runtimeFunctions) {
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) continue;

            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() == PcodeOp.CALLIND) {
                    Varnode targetFuncPtr = op.getInput(0);
                    if (isTaintedByGBS(targetFuncPtr, 0)) {
                        println("[SMM Callout 취약점 의심부 발견!]");
                        println("함수: " + func.getName());
                        println("주소: " + op.getSeqnum().getTarget());
                        vulnCount++;

                        String locJson = String.format("    {\n      \"function_name\": \"%s\",\n      \"pcode_address\": \"%s\"\n    }",
                                func.getName(), op.getSeqnum().getTarget());
                        locationsList.add(locJson);
                    }
                }
            }
        }

        // 수정된 부분: 문자열 "null"이 아닌 진짜 원시 타입 null 사용
        if (locationsList.isEmpty()) {
            String defaultNullLoc = "    {\n      \"function_name\": null,\n      \"pcode_address\": null\n    }";
            locationsList.add(defaultNullLoc);
        }

        if (vulnCount == 0) {
            println("\nSafe : 런타임(SMI)에서 gBS를 사용하는 Callout 패턴이 발견되지 않았습니다.");
        } else {
            println("\nWarning : 총 " + vulnCount + "개의 런타임 취약점 의심 지점이 발견되었습니다.");
        }

        String scriptName = "SmmCalloutHunter_v3";
        String binaryName = currentProgram.getName(); // 정상적인 파일 이름 추출
        Boolean vulnerabilityFound = vulnCount > 0;
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT);
        String info = vulnCount > 0 ? "런타임(SMI)에서 gBS를 참조하여 간접 호출하는 패턴이 발견됨" : "취약점 의심 패턴이 발견되지 않음";

        String locationsArrayString = String.join(",\n", locationsList);
        saveJsonToFile(scriptName, binaryName, vulnerabilityFound, timestamp, locationsArrayString, info);
    }

    private void buildRuntimeCallGraph(Function func, Set<Function> runtimeFunctions) {
        if (func == null || runtimeFunctions.contains(func)) return;
        runtimeFunctions.add(func);
        Set<Function> calledFunctions = func.getCalledFunctions(monitor);
        for (Function childFunc : calledFunctions) {
            buildRuntimeCallGraph(childFunc, runtimeFunctions);
        }
    }

    private boolean isTaintedByGBS(Varnode node, int depth) {
        if (node == null || depth > 10) return false;
        if (node.getAddress() != null && node.getAddress().isMemoryAddress()) {
            if (node.getAddress().equals(foundGbsAddr)) return true;
        }

        PcodeOp defOp = node.getDef();
        if (defOp == null) return false;

        int opcode = defOp.getOpcode();
        if (opcode == PcodeOp.LOAD) {
            Varnode addrNode = defOp.getInput(1);
            if (addrNode != null && addrNode.isConstant()) {
                Address sourceAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrNode.getOffset());
                if (sourceAddr.equals(foundGbsAddr)) return true;
            } else {
                return isTaintedByGBS(addrNode, depth + 1);
            }
        } else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST ||
                opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRADD ||
                opcode == PcodeOp.PTRSUB || opcode == PcodeOp.MULTIEQUAL ||
                opcode == PcodeOp.INDIRECT) {
            for (Varnode input : defOp.getInputs()) {
                if (isTaintedByGBS(input, depth + 1)) return true;
            }
        }
        return false;
    }

    private Varnode getParameterVarnode(Function func, int paramIndex) {
        DecompileResults results = decomp.decompileFunction(func, 30, monitor);
        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) return null;
        LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
        if (paramIndex >= lsm.getNumParams()) return null;
        HighSymbol paramSym = lsm.getParamSymbol(paramIndex);
        if (paramSym != null && paramSym.getHighVariable() != null) {
            return paramSym.getHighVariable().getRepresentative();
        }
        return null;
    }

    private void saveJsonToFile(String script_name, String binary_name, Boolean vulnerability_found, String timestamp, String locationsArrayString, String info) {
        // null 처리가 완벽하게 들어가도록 수정됨 (따옴표 제거)
        String json = String.format("{\n" +
                "  \"script_name\": \"%s\",\n" +
                "  \"binary_name\": \"%s\",\n" +
                "  \"vulnerability_found\": %s,\n" +
                "  \"timestamp\": \"%s\",\n" +
                "  \"locations\": [\n" +
                "%s\n" +
                "  ],\n" +
                "  \"info\": \"%s\"\n" +
                "}", script_name, binary_name, vulnerability_found, timestamp, locationsArrayString, info);

        try {
            String userHome = System.getProperty("user.home") + "/Desktop";
            String fileName = String.format("%s/%s_%s_report.json", userHome, binary_name, script_name);
            java.nio.file.Files.write(java.nio.file.Paths.get(fileName), json.getBytes());
            println("분석 결과가 JSON 파일로 저장되었습니다: " + fileName);
        } catch (Exception e) {
            println("JSON 파일 저장 중 오류 발생: " + e.getMessage());
        }
    }

    private void saveJsonToFileIfError(String errorMessage) {
        String scriptName = "SmmCalloutHunter_v3";
        // 수정: 조기 종료되더라도 해당 파일의 이름(binaryName)을 남기도록 변경
        String binaryName = currentProgram.getName();
        Boolean vulnerabilityFound = false;
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT);

        // 수정: 문자열 "null"이 아닌 진짜 JSON null 값으로 들어가도록 포맷 변경
        String locJson = "    {\n      \"function_name\": null,\n      \"pcode_address\": null\n    }";

        saveJsonToFile(scriptName, binaryName, vulnerabilityFound, timestamp, locJson, errorMessage);
    }

    private boolean hasOffsetE0(Varnode node, int depth) {
        if (node == null || depth > 10) return false;
        if (node.isConstant() && node.getOffset() == 0xE0) return true;
        PcodeOp def = node.getDef();
        if (def == null) return false;
        for (int i = 0; i < def.getNumInputs(); i++) {
            if (hasOffsetE0(def.getInput(i), depth + 1)) return true;
        }
        return false;
    }
}