import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.Address;
import java.util.ArrayList;
import java.util.List;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SmmCalloutHunter_v4_0_2 extends GhidraScript {
    // 디컴파일러
    private DecompInterface decomp;
    // 이미 방문한 함수 주소를 저장하여 무한 루프 방지
    private Set<Address> visitedFunctions = new HashSet<>();

    // Def-Use Chain에서 찾은 gBS 주소를 저장할 변수
    private Address foundGbsAddr = null;

    private long startTime;

    @Override
    protected void run() throws Exception {
        startTime = System.currentTimeMillis();

        println("==================================================");
        println("Starting SMM Callout using gBS...v4.0.1");
        println("==================================================");

        // ==================================================
        // [Phase 0-1] Triage: 이 파일이 SMM 드라이버가 맞는지 감별
        // ==================================================
        if (!isSmmDriver()) {
            println("Could not find SMM_BASE2_PROTOCOL");
            println("일반 DXE 드라이버이므로 종료.");
            String info = "SMM 드라이버가 아니어 조기 종료됨.";
            saveJsonToFileIfError(info);
            return;
        }

        println("SMM 드라이버 확인 완료. 본격적인 분석 시작.️");
        // 디컴파일러 초기화
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        // ==================================================
        // [Phase 0] find Handlers: 숨어있는 핸들러를 찾아내기
        // ==================================================

        // v4 수정 : SMI 핸들러을 찾는 로직을 완전히 새롭게 작성. 이제는 전체 함수를 뒤져서 CALLIND를 찾고, 그 주변에 0xE0이나 GUID가 있는지 보는 방식으로 변경
        List<Address> smiHandlers = findAndCreateSmiHandlers();

        println("==================================================");
        println("탐색 및 생성 완료!");


        // ==================================================
        // [Phase 1] Def-Use: gBS 전역 변수 위치 찾기
        // ==================================================
        println("gBS 전역 변수 탐색 시작");

        // 진입점 찾기
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
                    println("gBS 추적 실패. 스크립트를 종료합니다.");
                    String info = "gBS 전역 변수 위치를 찾지 못해 분석을 종료함.";
                    saveJsonToFileIfError(info);
                    return;
                }
            }
            else {
                println("Entry Point 파라미터 분석 실패.");
                String info = "Entry Point의 시스템 테이블 포인터를 찾지 못해 분석을 종료함.";
                saveJsonToFileIfError(info);
                return;
            }
        }
        else {
            println("Entry Point를 찾을 수 없습니다.");
            String info = "Entry Point를 찾지 못해 분석을 종료함.";
            saveJsonToFileIfError(info);
            return;
        }
        println("타겟 gBS 주소: " + foundGbsAddr);
        println("--------------------------------------------------");


        // ==================================================
        // [Phase 2] Use-Def: SMM Callout 취약점 스캔
        // ==================================================
        println("SMM Callout 취약점 스캔 시작!");
        println("--------------------------------------------------");

        scanForSmmCallouts(smiHandlers);

        println("모든 분석이 완료되었습니다.");
    }


    // Def-Use Chain을 타고 gBS 전역 변수의 위치를 찾는 함수들
    private boolean trackSystemTable(Function func, Varnode node, int depth) {
        if (node == null || depth > 10) {
            return false;
        }

        // 이 노드를 사용하는 PcodeOp를 순회
        Iterator<PcodeOp> uses = node.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            int opcode = op.getOpcode();

            // PTRADD : 포인터 값에 정수 오프셋을 더해 새 메모리 주소 계산
            // INT_ADD : PTRADD 말고 단순 정수 덧셈으로 계산하는 경우도 있을 수 있다
            if (opcode == PcodeOp.PTRADD || opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRSUB) {
                Varnode offsetNode = op.getInput(1);
                // 더하는 값이 상수이면서 0x60인지 확인 (gBS의 오프셋이 0x60이므로)
                if (offsetNode != null && offsetNode.isConstant() && offsetNode.getOffset() == 0x60) {
                    println("[+0x60 Catch!] 함수: " + func.getName());
                    if (checkIfStoredToGlobal(op.getOutput(), 0)) {
                        return true;
                    }
                }
            }
            // COPY나 CAST로 포인터가 한 번 더 꼬여있으면 더 깊게 파고들기
            else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
                if (trackSystemTable(func, op.getOutput(), depth)) {
                    return true;
                }
            }
            // CALL로 다른 함수에 매개변수로 넘어가는 경우도 추적 (recursive call)
            else if (opcode == PcodeOp.CALL) {
                Address targetAddr = op.getInput(0).getAddress();
                Function targetFunc = getFunctionAt(targetAddr);

                // 만약 이미 방문 한 곳이라면 패스
                if (targetFunc != null && !visitedFunctions.contains(targetAddr)) {
                    // paramIndex : 이 노드가 CALL에서 몇 번째 인자로 넘어가는지 찾기 (0번은 함수 포인터이므로 1번부터 시작)
                    // 이거는 한번 찾아보는걸로
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
                        if (trackSystemTable(targetFunc, nextNode, depth + 1)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    // 전역 변수로 들어가는지 추적하는 함수
    private boolean checkIfStoredToGlobal(Varnode ptrNode, int depth) {
        if (ptrNode == null || depth > 5) {
            return false;
        }
        Iterator<PcodeOp> uses = ptrNode.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            int opcode = op.getOpcode();

            // CAST 나 COPY로 한 번 더 꼬여있을 수 있으니 계속 추적
            if (opcode == PcodeOp.CAST || opcode == PcodeOp.COPY) {
                if (checkIfStoredToGlobal(op.getOutput(), depth + 1)) {
                    return true;
                }
            }

            // LOAD를 통해 메모리에서 들어오는 과정 역시 추적
            else if (opcode == PcodeOp.LOAD) {
                if (trackValueToMemory(op.getOutput(), 0)) {
                    return true;
                }
            }
        }
        return false;
    }

    // 메모리에서 읽어온 값이 gBS 전역 변수로 이어지는지 추적하는 함수
    // node : LOAD된 값을 받는 노드 (메모리에서 읽어온 값이 저장되는 곳)
    // depth : 재귀 깊이 (무한 루프 방지)
    private boolean trackValueToMemory(Varnode node, int depth) {
        if (node == null || depth > 5) {
            return false;
        }
        Iterator<PcodeOp> uses = node.getDescendants();
        while (uses.hasNext()) {
            PcodeOp op = uses.next();
            int opcode = op.getOpcode();

            if (opcode == PcodeOp.STORE) {
                Varnode destNode = op.getInput(1);
                if (destNode != null && destNode.isConstant()) {
                    foundGbsAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(destNode.getOffset());
                    println("gBS 전역 변수 발견: " + foundGbsAddr);

                    try {
                        // createLabel을 통해 시각화
                        createLabel(foundGbsAddr, "gBS_Global_Variable", true);
                    } catch (Exception e) {}
                    return true;
                }
            }
            else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST || opcode == PcodeOp.MULTIEQUAL || opcode == PcodeOp.INDIRECT) {
                Varnode destNode = op.getOutput();
                if (destNode != null) {
                    if (destNode.getAddress().isMemoryAddress()) {
                        foundGbsAddr = destNode.getAddress();
                        println("gBS 전역 변수 발견: " + foundGbsAddr);
                        try {
                            createLabel(foundGbsAddr, "gBS_Global_Variable", true);
                        } catch (Exception e) {}
                        return true;
                    } else {
                        if (trackValueToMemory(destNode, depth + 1)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    // -------------------------------------------------------
    // [Phase 2 Logic] 역방향 추적 (Use-Def) - SMM Callout 탐지
    // -------------------------------------------------------
    // v3 수정 : 모든 함수를 받아서 스캔하는 것이 아닌 찾은 핸들러들을 대상으로 수정
    // smiHandlers : Phase 1에서 찾아낸 SMI 핸들러들의 주소 리스트
    private void scanForSmmCallouts(List<Address> smiHandlers) {
        int vulnCount = 0;
        List<String> locationsList = new ArrayList<>();

        // 전체 함수를 스캔하는 대신, SMI 핸들러들과 그 자식 함수들만 스캔하기 위해 Set으로 중복 제거
        Set<Function> runtimeFunctions = new HashSet<>();

        // 찾아낸 SMI 핸들러들을 시작점으로 해서, 호출되는 모든 자식 함수(Call Graph)를 수집합니다.
        for (Address addr : smiHandlers) {
            Function handlerFunc = getFunctionAt(addr);
            if (handlerFunc != null) {
                buildRuntimeCallGraph(handlerFunc, runtimeFunctions);
            }
        }

        println("런타임 스캔 대상 함수 총 " + runtimeFunctions.size() + "개 추출 완료!");

        // 수집된 런타임 함수(SMI 핸들러 + 자식 함수)들만 스캔
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
                        println("원인: gBS 전역 변수를 참조하여 외부 함수를 호출함!");
                        vulnCount++;

                        String locJson = String.format("    {\n      \"function_name\": \"%s\",\n      \"pcode_address\": \"%s\"\n    }",
                                func.getName(), op.getSeqnum().getTarget());
                        locationsList.add(locJson);
                    }
                }
            }
        }

        // ... (아래 JSON 저장 로직은 기존과 100% 동일하게 유지) ...
        if (locationsList.isEmpty()) {
            String defaultNullLoc = "    {\n      \"function_name\": null,\n      \"pcode_address\": null\n    }";
            locationsList.add(defaultNullLoc);
        }

        if (vulnCount == 0) {
            println("\nSafe : 런타임(SMI)에서 gBS를 사용하는 Callout 패턴이 발견되지 않았습니다.");
        } else {
            println("\nWarning : 총 " + vulnCount + "개의 런타임 취약점 의심 지점이 발견되었습니다.");
        }

        String scriptName = "SmmCalloutHunter_v4_0_2";
        String binaryName = currentProgram.getName();
        Boolean vulnerabilityFound = vulnCount > 0 ? true : false;
        String timestamp = (System.currentTimeMillis() - startTime) / 1000.0 +"";
        String info = vulnCount > 0 ? "런타임(SMI)에서 gBS를 참조하여 간접 호출하는 패턴이 발견됨" : "취약점 의심 패턴이 발견되지 않음";

        String locationsArrayString = String.join(",\n", locationsList);
        saveJsonToFile(scriptName, binaryName, vulnerabilityFound, timestamp, locationsArrayString, info);
    }

    // SMI 핸들러 내부에서 호출되는 모든 자식 함수(런타임 함수)를 재귀적으로 수집.
    private void buildRuntimeCallGraph(Function func, Set<Function> runtimeFunctions) {
        if (func == null || runtimeFunctions.contains(func)) return;

        runtimeFunctions.add(func); // 수집 목록에 추가

        // 이 함수가 호출하는 다른 함수들(Called Functions)을 가져옵니다.
        Set<Function> calledFunctions = func.getCalledFunctions(monitor);
        for (Function childFunc : calledFunctions) {
            buildRuntimeCallGraph(childFunc, runtimeFunctions); // 재귀 추적
        }
    }

    // Taint Analysis를 통해 거꾸로 추적하는 함수
    private boolean isTaintedByGBS(Varnode node, int depth) {
        if (node == null || depth > 10) {
            return false;
        }

        if (node.getAddress() != null && node.getAddress().isMemoryAddress()) {
            if (node.getAddress().equals(foundGbsAddr)) {
                // System.out.println("   -> [디버그] 메모리 변수에서 gBS 역추적 성공!");
                return true;
            }
        }

        // 역추적을 해 연산자 가져오기
        PcodeOp defOp = node.getDef();
        if (defOp == null) {
            return false;
        }
        int opcode = defOp.getOpcode();

        // 메모리에서 읽어온거면 주소 확인
        if (opcode == PcodeOp.LOAD) {
            Varnode addrNode = defOp.getInput(1); // 읽어온 메모리 주소

            // 주소가 상수라면 그대로 비교
            if (addrNode != null && addrNode.isConstant()) {
                Address sourceAddr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrNode.getOffset());
                // 동일하다면 gBS에서 유래한 주소가 맞으므로 오염된 것으로 간주
                if (sourceAddr.equals(foundGbsAddr)) {
                    return true;
                }
            }
            // 계산이 된 경우라면 그 주소가 gBS에서 유래했는지 계속 추적
            else {
                return isTaintedByGBS(addrNode, depth + 1);
            }
        }

        else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST ||
                opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRADD ||
                opcode == PcodeOp.PTRSUB || opcode == PcodeOp.MULTIEQUAL ||
                opcode == PcodeOp.INDIRECT) {

            // 입력값들 중 하나라도 gBS에서 왔다면 오염된 것으로 간주
            for (Varnode input : defOp.getInputs()) {
                if (isTaintedByGBS(input, depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    // 유틸리티 함수
    private Varnode getParameterVarnode(Function func, int paramIndex) {
        DecompileResults results = decomp.decompileFunction(func, 30, monitor);
        HighFunction highFunc = results.getHighFunction();
        if (highFunc == null) {
            return null;
        }
        LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
        if (paramIndex >= lsm.getNumParams()) {
            return null;
        }
        HighSymbol paramSym = lsm.getParamSymbol(paramIndex);
        if (paramSym != null && paramSym.getHighVariable() != null) {
            return paramSym.getHighVariable().getRepresentative();
        }
        return null;
    }

    // JSON 저장 함수
    /*
    {
        "script_name": "string",
        "binary_name": "string",
        "vulnerability_found": boolean,
        "timestamp": "ISO 8601 format",
        "locations": [
            {
            "function_name": "string",
            "pcode_address": "string"
            }
        ],
        "info" : "string"
     */
    private void saveJsonToFile(String script_name, String binary_name, Boolean vulnerability_found, String timestamp, String locationsArrayString, String info) {

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
            String outputDir = System.getenv("OUTPUT_DIR");
            if (outputDir == null || outputDir.trim().isEmpty()) {
                outputDir = System.getProperty("user.home") + "/Desktop";
                println("OUTPUT_DIR 환경변수가 없어 Desktop 경로를 사용합니다.");
            }

            String normalizedBinary = binary_name;
            if (normalizedBinary.toLowerCase().endsWith(".efi")) {
                normalizedBinary = normalizedBinary.substring(0, normalizedBinary.length() - 4);
            }

            Path outputPath = Paths.get(outputDir);
            Files.createDirectories(outputPath);

            String reportFileName = String.format("%s_SmmCalloutHunter_report.json", normalizedBinary);
            Path reportPath = outputPath.resolve(reportFileName);
            Files.write(reportPath, json.getBytes(StandardCharsets.UTF_8));
            println("분석 결과가 JSON 파일로 저장되었습니다: " + reportPath.toString());
        } catch (Exception e) {
            println("JSON 파일 저장 중 오류 발생: " + e.getMessage());
        }
    }

    private List<Address> findAndCreateSmiHandlers() {
        List<Address> handlers = new ArrayList<>();

        // SW_DISPATCH2 GUID 바코드
        byte[] swDispatchGuid = new byte[] {
                (byte)0xdc, (byte)0xc6, (byte)0xa3, (byte)0x18, (byte)0xea, (byte)0x5e, (byte)0xc8, (byte)0x48,
                (byte)0xa1, (byte)0xc1, (byte)0xb5, (byte)0x33, (byte)0x89, (byte)0xf9, (byte)0x89, (byte)0x99
        };

        long guidOffset = -1;
        // SW_DISPATCH guid가 찍혀있는 위치가 있다면 offset을 저장
        try {
            Address guidAddr = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), swDispatchGuid, null, true, monitor);
            if (guidAddr != null) guidOffset = guidAddr.getOffset();
        } catch (Exception e) {}

        // 기존 방식 폐기. 전체 함수를 뒤지는 방향으로 수정
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) continue;

            boolean containsGuid = false;
            List<PcodeOp> callIndOps = new ArrayList<>();

            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();
                if (op.getOpcode() == PcodeOp.CALLIND) callIndOps.add(op);

                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode input = op.getInput(i);
                    if (input != null && input.isConstant() && input.getOffset() == guidOffset) {
                        containsGuid = true;
                    }
                }
            }

            for (PcodeOp op : callIndOps) {
                Varnode targetFuncPtr = op.getInput(0);

                // [타겟 1] Root 핸들러 (0xE0)
                if (hasOffsetE0(targetFuncPtr, 0)) {
                    Address handlerAddr = traceAddress(op.getInput(1)); // isConstant() 제거, 역추적 도입!
                    if (handlerAddr != null && currentProgram.getMemory().contains(handlerAddr)) {
                        handlers.add(handlerAddr);
                        println("\n[!] Root 핸들러(0xE0) 포착! (위치: " + func.getName() + ")");
                        createFuncIfNeeded(handlerAddr, "RootSmiHandler_" + handlerAddr.toString());
                    }
                }
                // [타겟 2] Child 핸들러 (GUID 포함 함수 내 간접호출)
                else if (containsGuid && op.getNumInputs() > 2) {
                    Address handlerAddr = traceAddress(op.getInput(2)); // isConstant() 제거, 역추적 도입!
                    if (handlerAddr != null && currentProgram.getMemory().contains(handlerAddr)) {
                        handlers.add(handlerAddr);
                        println("\n[!] Child 핸들러(SW_DISPATCH) 포착! (위치: " + func.getName() + ")");
                        createFuncIfNeeded(handlerAddr, "ChildSmiHandler_" + handlerAddr.toString());
                    }
                }
            }
        }
        return handlers;
    }

    //단순 상수(Constant)뿐만 아니라, 레지스터 연산(LEA, PTRSUB)에 담긴 주소까지 추적
    private Address traceAddress(Varnode node) {
        if (node == null) return null;

        // 운 좋게 상수로 바로 들어온 경우
        if (node.isConstant()) {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(node.getOffset());
        }

        PcodeOp def = node.getDef();
        if (def == null) return null;

        int opcode = def.getOpcode();
        // 레지스터 복사(COPY)나 형변환(CAST)이 일어났다면 그 이전 출처를 쫓아감
        if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST) {
            return traceAddress(def.getInput(0));
        }
        // 어셈블리 LEA 명령어 (P-Code로는 보통 PTRSUB로 번역됨)를 통해 주소를 계산한 경우
        else if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.PTRADD) {
            Varnode offset = def.getInput(1);
            if (offset != null && offset.isConstant()) {
                return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset.getOffset());
            }
        }
        return null;
    }
    // 연산 트리를 재귀적으로 파고들며 0xE0(SmmHandlerRegister)를 찾는 함수
    private boolean hasOffsetE0(Varnode node, int depth) {
        // 너무 깊게 들어가면 추적 종료
        if (node == null || depth > 10) {
            return false;
        }

        // 상수가 0xE0 (십진수 224) 이면 추적 성공
        if (node.isConstant() && node.getOffset() == 0xE0) {
            return true;
        }

        PcodeOp def = node.getDef();
        // 정의가 없는 노드면 추적 종료
        if (def == null) {
            return false;
        }

        // LOAD, COPY, CAST, PTRADD 등 이 노드를 만든 부모 연산자의 입력값들을 전부 추적
        for (int i = 0; i < def.getNumInputs(); i++) {
            if (hasOffsetE0(def.getInput(i), depth + 1)) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------
    // [Phase 0 Logic] SMM 드라이버 감별 함수 (GUID 스캔)
    // -------------------------------------------------------
    private boolean isSmmDriver() {
        // gEfiSmmBase2ProtocolGuid = { 0xf4ccbfb7, 0xf6e0, 0x47fd, { 0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1, 0x91 } }
        // 메모리에 올라갈 때는 리틀 엔디안(Little-Endian) 방식으로 뒤집혀서 저장됩니다.
        byte[] smmBase2Guid = new byte[] {
                (byte)0xb7, (byte)0xbf, (byte)0xcc, (byte)0xf4, // 0xf4ccbfb7
                (byte)0xe0, (byte)0xf6,                         // 0xf6e0
                (byte)0xfd, (byte)0x47,                         // 0x47fd
                (byte)0x9d, (byte)0xd4, (byte)0x10, (byte)0xa8, (byte)0xf1, (byte)0x50, (byte)0xc1, (byte)0x91
        };

        try {
            // 프로그램 전체 메모리에서 해당 16바이트 GUID 패턴을 싹 뒤집니다.
            Address foundAddr = currentProgram.getMemory().findBytes(
                    currentProgram.getMinAddress(),
                    smmBase2Guid,
                    null,
                    true,
                    monitor
            );

            // 발견되었다면 이 녀석은 SMM 환경에 진입하려 한 SMM 드라이버.
            if (foundAddr != null) {
                println("[SMM_BASE2_PROTOCOL GUID] 발견! 위치: " + foundAddr);
                return true;
            }
        } catch (Exception e) {
            println("GUID 검색 중 오류: " + e.getMessage());
        }

        return false;
    }

    private void saveJsonToFileIfError(String errorMessage) {
        String scriptName = "SmmCalloutHunter_v4_0_2";
        String binaryName = currentProgram.getName();
        Boolean vulnerabilityFound = false;
        String timestamp = (System.currentTimeMillis() - startTime) / 1000.0 +"";

        String locJson = String.format("    {\n      \"function_name\": \"%s\",\n      \"pcode_address\": \"%s\"\n    }",
                null, null);
        saveJsonToFile(scriptName, binaryName, vulnerabilityFound, timestamp, locJson, errorMessage);
    }



    // 함수 강제 생성 유틸리티
    private void createFuncIfNeeded(Address addr, String name) {
        if (getFunctionAt(addr) == null) {
            try {
                disassemble(addr);
                createFunction(addr, name);
                println("  -> 기드라에 새 함수 생성 완료: " + name);
            } catch (Exception e) {}
        }
    }
}