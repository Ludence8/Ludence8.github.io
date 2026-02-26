import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.Address;
import java.util.Iterator;
import java.util.HashSet;
import java.util.Set;

public class SmmCalloutHunter extends GhidraScript {

    // 디컴파일러
    private DecompInterface decomp;
    // 이미 방문한 함수 주소를 저장하여 무한 루프 방지
    private Set<Address> visitedFunctions = new HashSet<>();

    // Def-Use Chain에서 찾은 gBS 주소를 저장할 변수
    private Address foundGbsAddr = null;

    @Override
    protected void run() throws Exception {
        println("==================================================");
        println("Starting SMM Callout using gBS...");
        println("==================================================");

        // 디컴파일러 초기화
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // ==================================================
        // [Phase 1] Def-Use: gBS 전역 변수 위치 찾기
        // ==================================================
        println("gBS 전역 변수 탐색 시작!");

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

                if (!found) {
                    println("gBS 추적 실패. 스크립트를 종료합니다.");
                    return;
                }
            }
            else {
                println("Entry Point 파라미터 분석 실패.");
                return;
            }
        }
        else {
            println("Entry Point를 찾을 수 없습니다.");
            return;
        }
        println("타겟 gBS 주소: " + foundGbsAddr);
        println("--------------------------------------------------");


        // ==================================================
        // [Phase 2] Use-Def: SMM Callout 취약점 스캔
        // ==================================================
        println("\nSMM Callout 취약점 스캔 시작!");
        println("--------------------------------------------------");

        scanForSmmCallouts();

        println("\n모든 분석이 완료되었습니다.");
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
            // PTRSUB : + 0x60이 아니라 -0x60으로 접근하는 경우도 있을 수 있다
            if (opcode == PcodeOp.PTRADD || opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRSUB) {
                Varnode offsetNode = op.getInput(1);
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

    // LOAD 추적 함수
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
    private void scanForSmmCallouts() {
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int vulnCount = 0;

        while (funcs.hasNext()) {
            Function func = funcs.next();
            // 함수별로 디컴파일 수행
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null) continue;

            Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOp op = ops.next();

                // 간접 호출 발견
                // 직접 호출은 절대 좌표를 통해 하드코딩해야 하기 때문에, 레지스터나 계산된 주소로 호출하는 간접 호출.
                if (op.getOpcode() == PcodeOp.CALLIND) {
                    Varnode targetFuncPtr = op.getInput(0); // 호출하려는 주소값(RAX 등)

                    // 역추적 결과가 gBS라면?
                    if (isTaintedByGBS(targetFuncPtr, 0)) {
                        println("\n[SMM Callout 취약점 의심부 발견!]");
                        println("함수: " + func.getName());
                        println("주소: " + op.getSeqnum().getTarget());
                        println("원인: gBS 전역 변수를 참조하여 외부 함수를 호출함!");
                        vulnCount++;
                    }
                }
            }
        }

        if (vulnCount == 0) {
            println("\nSafe : gBS를 사용하는 Callout 패턴이 발견되지 않았습니다.");
        } else {
            println("\n총 " + vulnCount + "개의 취약점 의심 지점이 발견되었습니다.");
        }
    }

    // Taint Analysis를 통해 거꾸로 추적하는 함수
    private boolean isTaintedByGBS(Varnode node, int depth) {
        if (node == null || depth > 10) {
            return false;
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

        // 단순 복사 및 이동일 경우
        else if (opcode == PcodeOp.COPY || opcode == PcodeOp.CAST ||
                opcode == PcodeOp.INT_ADD || opcode == PcodeOp.PTRADD ||
                opcode == PcodeOp.MULTIEQUAL || opcode == PcodeOp.INDIRECT) {

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
}