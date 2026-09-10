-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_File_IO; with Pkg_RPM;
with Test_Support; use Test_Support;
procedure Run_RPM_Tests with SPARK_Mode => Off is
   use type Byte;
   Good : Bytes := MC_File_IO.Read_File("fixtures/metadata-only-unsigned.rpm");
   Hooks : constant Bytes := MC_File_IO.Read_File("fixtures/hook-metadata-only-unsigned.rpm");
   Short : constant Bytes := MC_File_IO.Read_File("fixtures/truncated.rpm");
   Huge_Count : constant Bytes := MC_File_IO.Read_File("fixtures/excessive-index-count.rpm");
   Bad_Lead : constant Bytes := MC_File_IO.Read_File("fixtures/invalid-lead.rpm");
   Info : Pkg_RPM.Metadata;
   Status : Outcome;
begin
   Pkg_RPM.Inspect(Good,Info,Status);
   Expect(Status=OK,"rpm-valid-header-fixture");
   Expect(not Info.Has_Signature_Tag,"rpm-unsigned-is-not-authenticated");
   Expect(not Info.Has_Executable_Hooks,"rpm-no-hook-fixture");
   Pkg_RPM.Inspect(Hooks,Info,Status);
   Expect(Status=OK and then Info.Has_Executable_Hooks,"rpm-hook-detected-not-executed");
   Pkg_RPM.Inspect(Short,Info,Status); Expect(Status/=OK,"rpm-truncation");
   Pkg_RPM.Inspect(Huge_Count,Info,Status); Expect(Status/=OK,"rpm-count-bound");
   Pkg_RPM.Inspect(Bad_Lead,Info,Status); Expect(Status/=OK,"rpm-lead-magic");
   for J in 0..111 loop
      Pkg_RPM.Inspect(Good(1..J),Info,Status); Expect(Status/=OK,"rpm-all-prefixes");
   end loop;
   for J in Good'Range loop
      Good(J) := Good(J) xor 16#FF#;
      Pkg_RPM.Inspect(Good,Info,Status);
      Expect(Status/=OK or else Info.Payload_Offset<=Good'Length,"rpm-mutant-bounds");
      Good(J) := Good(J) xor 16#FF#;
   end loop;
   Report;
end Run_RPM_Tests;
