-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Text; with MC_SHA256;
with Pkg_Dependency; with Pkg_File_Plan; with Pkg_EVR;
with MC_Codec; with Pkg_Artifact_Grant;
with Pkg_RPM; with Pkg_RPM_Fields;
with Test_Support; use Test_Support;
procedure Run_V2_Pkg_Tests with SPARK_Mode=>Off is
   type Providers_Access is access Pkg_Dependency.Provider_Array;
   Providers : constant Providers_Access := new Pkg_Dependency.Provider_Array; Selected : Pkg_Dependency.Selection:=(others=>False);
   E : Pkg_Dependency.Expression; S : Outcome; Yes : Boolean;
   type Plan_Access is access Pkg_File_Plan.Plan;
   P,Q : constant Plan_Access := new Pkg_File_Plan.Plan; Data : Bytes(1..16_384); Used : Natural;
   procedure Expression(T : String; Expected : Boolean) is
   begin
      Pkg_Dependency.Parse(T,E,S); Expect(S=OK,"parse-rich-dependency");
      Pkg_Dependency.Evaluate(E,Providers.all,2,Selected,Yes,S); Expect(S=OK and then Yes=Expected,"evaluate-rich-dependency");
   end;
begin
   declare
      M : Pkg_RPM.Metadata;
      B : constant Bytes(1..4):=(65,0,0,42);
      V : Wide; T : MC_Text.Value;
      use type Wide;
   begin
      M.Entry_Count:=1;
      M.Entries(1):=(Tag=>1,Data_Type=>6,Data_Offset=>0,Item_Count=>1,Span=>2);
      Pkg_RPM_Fields.Text(B,M,1,1,T,S);
      Expect(S=OK and then MC_Text.Image(T)="A","rpm-field-valid-text");
      M.Entries(1).Data_Offset:=Natural'Last;
      Pkg_RPM_Fields.Text(B,M,1,1,T,S);
      Expect(S=Invalid_Input and then MC_Text.Length(T)=0,"rpm-field-invalid-offset");
      M.Entries(1).Data_Offset:=0; M.Entries(1).Span:=Natural'Last;
      Pkg_RPM_Fields.Text(B,M,1,1,T,S);
      Expect(S=Invalid_Input,"rpm-field-invalid-span");
      M.Entries(1):=(Tag=>1,Data_Type=>3,Data_Offset=>2,Item_Count=>1,Span=>2);
      Pkg_RPM_Fields.Number(B,M,1,1,V,S);
      Expect(S=OK and then V=42,"rpm-field-valid-number");
      M.Entries(1).Span:=1;
      Pkg_RPM_Fields.Number(B,M,1,1,V,S);
      Expect(S=Invalid_Input and then V=0,"rpm-field-number-outside-declared-span");
      M.Entries(1).Item_Count:=Natural'Last; M.Entries(1).Span:=Natural'Last;
      Pkg_RPM_Fields.Number(B,M,1,Positive'Last,V,S);
      Expect(S=Invalid_Input and then V=0,"rpm-field-invalid-item-count");
   end;
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
   Expect(Pkg_File_Plan.Layout_Valid(P.all),"bounded-file-plan");
   Pkg_File_Plan.Encode(P.all,Data,Used,S); Expect(S=OK,"file-plan-encode");
   Pkg_File_Plan.Decode(Data(1..Used),Q.all,S); Expect(S=OK and then Q.Count=1,"file-plan-decode");
   MC_Codec.Put32(Data,137,2);
   Pkg_File_Plan.Decode(Data(1..Used),Q.all,S);
   Expect(S/=OK,"file-plan-missing-second-entry-is-not-success");
   MC_Codec.Put32(Data,137,1);
   Data(141):=1; Pkg_File_Plan.Decode(Data(1..Used),Q.all,S); Expect(S/=OK,"file-plan-unknown-field");
   P.Changes(1).Domain:=Pkg_File_Plan.Business_Data; Expect(not Pkg_File_Plan.Layout_Valid(P.all),"business-data-not-package-rollback");
   P.Changes(1).Domain:=Pkg_File_Plan.Packaged_Files; P.Changes(1).After.Mode:=8#4755#;
   Expect(not Pkg_File_Plan.Layout_Valid(P.all),"setuid-not-supported");
   Expect(not Pkg_File_Plan.Allowed_Path("etc/shadow"),"secrets-not-packaged");
   Expect(not Pkg_File_Plan.Allowed_Path("../etc/passwd"),"traversal-denied");
   Expect(not Pkg_File_Plan.Allowed_Path("usr/.mc-tmp-forged"),"reserved-engine-path");
   declare
      Empty_Text : String(-1..-2);
      Last_Colon : constant String(Integer'Last-1..Integer'Last):="1:";
      Last_Version : constant String(Integer'Last..Integer'Last):="1";
      Version : Pkg_EVR.EVR;
   begin
      Expect(not Pkg_File_Plan.Allowed_Path(Empty_Text),"file-plan-null-negative-origin-path");
      Pkg_Dependency.Parse(Empty_Text,E,S);
      Expect(S=Invalid_Input,"dependency-null-negative-origin");
      Pkg_EVR.Parse(Empty_Text,Version,S);
      Expect(S=Invalid_Input,"evr-null-negative-origin");
      Pkg_EVR.Parse(Last_Colon,Version,S);
      Expect(S=Invalid_Input,"evr-final-colon-last-index");
      Pkg_EVR.Parse(Last_Version,Version,S);
      Expect(S=OK and then MC_Text.Image(Version.Version)="1","evr-valid-last-index");
   end;
   declare
      URL : constant String := "https://repo.example/pkg";
      Frame_Length : constant Positive := 160+URL'Length;
      High_Frame : Bytes(Integer'Last-(Frame_Length-1) .. Integer'Last);
      Normal_Frame : Bytes(1..Frame_Length);
      Short_Frame : Bytes(1..1);
      G, Decoded : Pkg_Artifact_Grant.Grant;
      use type Pkg_Artifact_Grant.Grant;
   begin
      G.Repository:=(others=>1); G.Object:=(others=>2);
      G.Snapshot:=(others=>3); G.Contract:=(others=>4);
      G.Revision:=1; G.Issued:=10; G.Expires:=20; G.Size:=1;
      MC_Text.Set(G.URL,URL,S); Expect(S=OK,"artifact-grant-url");
      Pkg_Artifact_Grant.Encode(G,Normal_Frame,Used,S);
      Expect(S=OK and then Used=Frame_Length,"artifact-grant-encode");
      Pkg_Artifact_Grant.Encode(G,High_Frame,Used,S);
      Expect(S=OK and then Used=Frame_Length and then High_Frame=Normal_Frame,
        "artifact-grant-output-last-index");
      Pkg_Artifact_Grant.Decode(High_Frame,Decoded,S);
      Expect(S=OK and then Decoded=G,"artifact-grant-high-index-roundtrip");
      Pkg_Artifact_Grant.Encode(G,Short_Frame,Used,S);
      Expect(S/=OK and then Used=0,"artifact-grant-short-output");
   end;
   Report;
end Run_V2_Pkg_Tests;
