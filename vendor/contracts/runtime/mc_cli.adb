-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types;
with MC_Contract_Profile; with MC_Stop_Barrier; with MC_Stop_Barrier_Auth;
with MC_Health_Report; with MC_Health_Golden; with MC_Authentic;
with MC_Protocol; with MC_Golden; with MC_Hex; with MC_File_IO; with MC_Signatures;
package body MC_CLI with SPARK_Mode => Off is
   function Handle_Common return Boolean is
      use Ada.Command_Line; use Ada.Text_IO;
      Status : Outcome;
      H : MC_Protocol.Header;
   begin
      if Argument_Count = 0 then return False; end if;
      if Argument(1) = "contract-profile" and then Argument_Count=1 then
         Put_Line(MC_Hex.Encode(MC_Contract_Profile.Fingerprint)); return True;
      elsif Argument(1) = "contract-vector" and then Argument_Count=1 then
         Put_Line(MC_Hex.Encode(MC_Protocol.Encode(MC_Golden.Header))); return True;
      elsif Argument(1) = "recovery-contract-vector" and then Argument_Count=1 then
         Put_Line(MC_Hex.Encode(MC_Health_Report.Encode(MC_Health_Golden.Value))); return True;
      elsif Argument(1) = "check-stop-policy" and then Argument_Count=2 then
         declare B : constant Bytes := MC_File_IO.Read_File(Argument(2),4_608);
            P : MC_Stop_Barrier.Policy;
         begin MC_Stop_Barrier.Decode(B,P,Status); end;
         Put_Line("structural_status=" & Outcome'Image(Status));
         Put_Line("policy_authority_checked=false inventory_checked=false authorized=false");
         if Status/=OK then Set_Exit_Status(Failure); end if; return True;
      elsif Argument(1) = "check-stop-state" and then Argument_Count=2 then
         declare B : constant Bytes := MC_File_IO.Read_File(Argument(2),4_608);
            S : MC_Stop_Barrier.State;
         begin MC_Stop_Barrier.Decode(B,S,Status); end;
         Put_Line("structural_status=" & Outcome'Image(Status));
         Put_Line("latest_state_checked=false freshness_checked=false authorized=false");
         if Status/=OK then Set_Exit_Status(Failure); end if; return True;
      elsif Argument(1) = "verify-stop-evidence" and then Argument_Count=4 then
         declare
            PB : constant Bytes := MC_File_IO.Read_File(Argument(2),4_608);
            EB : constant Bytes := MC_File_IO.Read_File(Argument(3),320);
            Sig : constant Bytes := MC_File_IO.Read_File(Argument(4),64);
            P : MC_Stop_Barrier.Policy; E : MC_Stop_Barrier.Evidence;
         begin
            MC_Stop_Barrier.Decode(PB,P,Status);
            if Status=OK then
               if Sig'Length/=64 then Status:=Invalid_Input;
               else MC_Stop_Barrier_Auth.Verify(P,EB,Sig,E,Status); end if;
            end if;
            Put_Line("signature_and_structure=" & Outcome'Image(Status));
            Put_Line("policy_authority_checked=false observation_truth_checked=false authorized=false");
            if Status/=OK then Set_Exit_Status(Failure); end if;
         end; return True;
      elsif Argument(1) = "check-health-frame" and then Argument_Count=2 then
         declare Raw : constant Bytes := MC_File_IO.Read_File(Argument(2),256);
            Report : MC_Health_Report.Report;
         begin MC_Health_Report.Decode(Raw,Report,Status); end;
         Put_Line("structural_status=" & Outcome'Image(Status));
         Put_Line("authenticated=false freshness_checked=false authorized=false");
         if Status/=OK then Set_Exit_Status(Failure); end if; return True;
      elsif Argument(1) = "verify-health-report" and then Argument_Count=4 then
         declare Raw : constant Bytes := MC_File_IO.Read_File(Argument(2),256);
            Sig : constant Bytes := MC_File_IO.Read_File(Argument(3),64);
            Key : constant Bytes := MC_File_IO.Read_File(Argument(4),32);
            Report : MC_Health_Report.Report;
         begin
            Status:=Invalid_Input;
            if Sig'Length=64 and then Key'Length=32 then
               MC_Authentic.Verify("MC-HEALTH-v1",Raw,Sig,Key,Status);
               if Status=OK then MC_Health_Report.Decode(Raw,Report,Status); end if;
            end if;
            Put_Line("signature_and_structure=" & Outcome'Image(Status));
            Put_Line("key_trust_checked=false freshness_checked=false authorized=false");
            if Status/=OK then Set_Exit_Status(Failure); end if;
         end; return True;
      elsif Argument(1) = "check-header" and then Argument_Count=2 then
         declare Raw : constant Bytes := MC_File_IO.Read_File(Argument(2),160);
         begin MC_Protocol.Decode(Raw,H,Status); end;
         Put_Line("structural_status=" & Outcome'Image(Status));
         Put_Line("authenticated=false authorized=false");
         if Status/=OK then Set_Exit_Status(Failure); end if;
         return True;
      elsif Argument(1) = "verify-envelope" and then Argument_Count=5 then
         declare
            Raw : constant Bytes := MC_File_IO.Read_File(Argument(2),160);
            Body_Data : constant Bytes := MC_File_IO.Read_File(Argument(3),Max_Message);
            Sig : constant Bytes := MC_File_IO.Read_File(Argument(4),64);
            Key : constant Bytes := MC_File_IO.Read_File(Argument(5),32);
            Message : MC_Signatures.Verified_Message;
         begin
            if Sig'Length/=64 or else Key'Length/=32 then
               Put_Line("signature_status=INVALID_INPUT authorized=false");
               Set_Exit_Status(Failure); return True;
            end if;
            MC_Signatures.Verify(Raw,Body_Data,Sig,Key,Message,Status);
            Put_Line("signature_status=" & Outcome'Image(Status));
            Put_Line("scope_checked=false replay_checked=false authorized=false");
            if Status/=OK then Set_Exit_Status(Failure); end if;
         end;
         return True;
      end if;
      return False;
   end Handle_Common;
end MC_CLI;
