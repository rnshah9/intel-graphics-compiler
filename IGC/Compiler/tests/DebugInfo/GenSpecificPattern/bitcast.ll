;=========================== begin_copyright_notice ============================
;
; Copyright (C) 2022 Intel Corporation
;
; SPDX-License-Identifier: MIT
;
;============================ end_copyright_notice =============================
;
; RUN: igc_opt --igc-gen-specific-pattern -S < %s | FileCheck %s
; ------------------------------------------------
; GenSpecificPattern: bitcast pattern
; ------------------------------------------------
; This test checks that GenSpecificPattern pass follows
; 'How to Update Debug Info' llvm guideline.
;
; Debug MD for this test was created with debugify pass.
; ------------------------------------------------

source_filename = "BitcastPattern.ll"

define spir_kernel void @test_bitcast(i32 %src1, i32 %src2) !dbg !6 {
entry:
; Testcase1:
; CHECK-DAG: [[LINE5:![0-9]+]] = !DILocation(line: 5
; CHECK-DAG: [[BITCAST_MD:![0-9]+]] = !DILocalVariable(name: "5"
; CHECK-DAG: dbg.value(metadata double [[BITCAST_V:%[0-9]*]],  metadata [[BITCAST_MD]]
; CHECK-DAG: [[BITCAST_V]] = bitcast <2 x i32> {{.*}}, !dbg [[LINE5]]
  %0 = insertelement <2 x i32> <i32 0, i32 undef>, i32 %src1, i32 1, !dbg !15
  call void @llvm.dbg.value(metadata <2 x i32> %0, metadata !9, metadata !DIExpression()), !dbg !15
  %1 = bitcast <2 x i32> %0 to i64, !dbg !16
  call void @llvm.dbg.value(metadata i64 %1, metadata !11, metadata !DIExpression()), !dbg !16
  %2 = zext i32 %src2 to i64, !dbg !17
  call void @llvm.dbg.value(metadata i64 %2, metadata !12, metadata !DIExpression()), !dbg !17
  %3 = or i64 %1, %2, !dbg !18
  call void @llvm.dbg.value(metadata i64 %3, metadata !13, metadata !DIExpression()), !dbg !18
  %4 = bitcast i64 %3 to double, !dbg !19
  call void @llvm.dbg.value(metadata double %4, metadata !14, metadata !DIExpression()), !dbg !19
  ret void, !dbg !20
}

; Function Attrs: nounwind readnone speculatable
declare void @llvm.dbg.value(metadata, metadata, metadata) #0

attributes #0 = { nounwind readnone speculatable  }

!llvm.dbg.cu = !{!0}
!llvm.debugify = !{!3, !4}
!llvm.module.flags = !{!5}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: "debugify", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2)
!1 = !DIFile(filename: "BitcastPattern.ll", directory: "/")
!2 = !{}
!3 = !{i32 6}
!4 = !{i32 5}
!5 = !{i32 2, !"Debug Info Version", i32 3}
!6 = distinct !DISubprogram(name: "test_bitcast", linkageName: "test_bitcast", scope: null, file: !1, line: 1, type: !7, scopeLine: 1, unit: !0, retainedNodes: !8)
!7 = !DISubroutineType(types: !2)
!8 = !{!9, !11, !12, !13, !14}
!9 = !DILocalVariable(name: "1", scope: !6, file: !1, line: 1, type: !10)
!10 = !DIBasicType(name: "ty64", size: 64, encoding: DW_ATE_unsigned)
!11 = !DILocalVariable(name: "2", scope: !6, file: !1, line: 2, type: !10)
!12 = !DILocalVariable(name: "3", scope: !6, file: !1, line: 3, type: !10)
!13 = !DILocalVariable(name: "4", scope: !6, file: !1, line: 4, type: !10)
!14 = !DILocalVariable(name: "5", scope: !6, file: !1, line: 5, type: !10)
!15 = !DILocation(line: 1, column: 1, scope: !6)
!16 = !DILocation(line: 2, column: 1, scope: !6)
!17 = !DILocation(line: 3, column: 1, scope: !6)
!18 = !DILocation(line: 4, column: 1, scope: !6)
!19 = !DILocation(line: 5, column: 1, scope: !6)
!20 = !DILocation(line: 6, column: 1, scope: !6)
