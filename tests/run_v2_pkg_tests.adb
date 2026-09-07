-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Text; with MC_SHA256;
with Pkg_Dependency; with Pkg_File_Plan; with Pkg_EVR;
with Test_Support; use Test_Support;
procedure Run_V2_Pkg_Tests with SPARK_Mode=>Off is
   Providers : Pkg_Dependency.Provider_Array; Selected : Pkg_Dependency.Selection:=(others=>False);
   E : Pkg_Dependency.Expression; S : Outcome; Yes : Boolean;
   P,Q : Pkg_File_Plan.Plan; Data : Bytes(1..16_384); Used : Natural;
   procedure Expression(T : String; Expected : Boolean) is
   begin
      Pkg_Dependency.Parse(T,E,S); Expect(S=OK,"parse-rich-dependency");
      Pkg_Dependency.Evaluate(E,Providers,2,Selected,Yes,S); Expect(S=OK and then Yes=Expected,"evaluate-rich-dependency");
   end;
begin
   Providers(1).Package_Index:=1; Providers(2).Package_Index:=2;
   MC_Text.Set(Providers(1).Name,"A",S); MC_Text.Set(Providers(2).Name,"B",S);
   Selected(1):=True; Selected(2):=True;
   Expression("(A and B)",True); Expression("(A with B)",False);
   Providers(2).Package_Index:=1; Expression("(A with B)",True); Expression("(A without B)",False);
   Providers(2).Package_Index:=2; Selected(2):=False; Expression("(A without B)",True);
   Expression("(C if B)",True); Expression("(C unless A)",True);
   Pkg_Dependency.Parse("(A mystery B)",E,S); Expect(S/=OK,"unknown-dependency-operator");
   P.Root_ID:=(others=>1); P.Transaction_ID:=(others=>2); P.Epoch:=1; P.Fence:=1;
   P.Target_Generation:=1; P.Package_Set:=(others=>3); P.Effect_Contract:=(others=>4); P.Count:=1;
   MC_Text.Set(P.Changes(1).Path,"usr/application",S);
   P.Changes(1).After:=(Node_Kind=>Pkg_File_Plan.Regular,Mode=>8#644#,Size=>3,
     Content=>MC_SHA256.Hash(Bytes'(97,98,99)),Xattrs=>MC_SHA256.Hash(Bytes'(0,0)),others=><>);
   Expect(Pkg_File_Plan.Layout_Valid(P),"bounded-file-plan");
   Pkg_File_Plan.Encode(P,Data,Used,S); Expect(S=OK,"file-plan-encode");
   Pkg_File_Plan.Decode(Data(1..Used),Q,S); Expect(S=OK and then Q.Count=1,"file-plan-decode");
   Data(141):=1; Pkg_File_Plan.Decode(Data(1..Used),Q,S); Expect(S/=OK,"file-plan-unknown-field");
   P.Changes(1).Domain:=Pkg_File_Plan.Business_Data; Expect(not Pkg_File_Plan.Layout_Valid(P),"business-data-not-package-rollback");
   P.Changes(1).Domain:=Pkg_File_Plan.Packaged_Files; P.Changes(1).After.Mode:=8#4755#;
   Expect(not Pkg_File_Plan.Layout_Valid(P),"setuid-not-supported");
   Expect(not Pkg_File_Plan.Allowed_Path("etc/shadow"),"secrets-not-packaged");
   Expect(not Pkg_File_Plan.Allowed_Path("../etc/passwd"),"traversal-denied");
   Expect(not Pkg_File_Plan.Allowed_Path("usr/.mc-tmp-forged"),"reserved-engine-path");
   Report;
end Run_V2_Pkg_Tests;
