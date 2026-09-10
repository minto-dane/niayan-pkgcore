-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Text_IO;
with MC_Types; use MC_Types; with MC_Text; with MC_Properties; with MC_File_IO;
with MC_Clock; with MC_Runtime; with MC_Hex; with MC_Numbers; with MC_FS; with MC_Atomic;
with MC_Contract_Profile;
with MC_Health_Report;
with MC_Keys; with MC_Signatures; with MC_Site_Policy; with MC_Witness; with MC_Protocol; with MC_Requests;
with MC_SHA256; with MC_Codec; with MC_Request_Files; with MC_Gate;
package body MC_Admin with SPARK_Mode => Off is
   use Ada.Command_Line; use Ada.Text_IO;
   function Handle return Boolean is
      D : MC_Properties.Document; V : MC_Text.Value; S : Outcome; Dir : MC_FS.Root; Lock : MC_FS.File;
      P,Old,Decoded : MC_Site_Policy.Policy; Frame : MC_Site_Policy.Frame; Digest_Of_Policy : Digest;
      H : MC_Protocol.Header; R : MC_Requests.Request; W : MC_Witness.Statement;
      PK : MC_Signatures.Public_Key; Sig : MC_Signatures.Signature; Now,UTC : Counter; Boot : Identity;
      function Is_Command(Name : String; Count : Natural) return Boolean is
        (Argument_Count=Count and then Argument(1)=Name);
      procedure Field(K : String; B : out Bytes) is
      begin
         if S/=OK then B:=(others=>0); return; end if;
         MC_Properties.Get(D,K,V,S); if S=OK then MC_Hex.Decode(MC_Text.Image(V),B,S); end if;
      end;
      procedure Number(K : String; N : out Counter) is
      begin
         N:=0; if S/=OK then return; end if;
         MC_Properties.Get(D,K,V,S); if S=OK then MC_Numbers.Parse(MC_Text.Image(V),N,S); end if;
      end;
      procedure Load_Spec(Keys : String) is
      begin
         MC_Properties.Parse(MC_File_IO.Read_File(Argument(2),64*4_160),D,S);
         if S=OK and then not MC_Properties.Has_Exactly(D,Keys) then S:=Invalid_Input; end if;
      end;
      function Action_Name(A : MC_Requests.Requested_Action) return String is
        (case A is when MC_Requests.Plan=>"plan", when MC_Requests.Prepare=>"prepare", when MC_Requests.Apply=>"apply",
         when MC_Requests.Inspect=>"inspect", when MC_Requests.Recover=>"recover", when MC_Requests.Commit=>"commit",
         when MC_Requests.Restore=>"restore", when MC_Requests.Reconcile=>"reconcile", when MC_Requests.Repair=>"repair");
      function Header_Kind(A : MC_Requests.Requested_Action) return MC_Protocol.Message_Kind is
        (case A is when MC_Requests.Plan=>MC_Protocol.Plan_Request, when MC_Requests.Prepare=>MC_Protocol.Prepare_Request,
         when MC_Requests.Apply=>MC_Protocol.Apply_Request, when MC_Requests.Inspect=>MC_Protocol.Inspect_Request,
         when MC_Requests.Recover=>MC_Protocol.Recover_Request, when MC_Requests.Commit=>MC_Protocol.Commit_Request,
         when MC_Requests.Restore=>MC_Protocol.Restore_Request, when MC_Requests.Reconcile=>MC_Protocol.Reconcile_Request,
         when MC_Requests.Repair=>MC_Protocol.Repair_Request);
      procedure Result is
      begin
         MC_FS.Close(Lock); MC_FS.Close(Dir); Put_Line("administrative-operation=" & Outcome'Image(S));
         if S/=OK then Set_Exit_Status(Failure); end if;
      end;
   begin
      if Argument_Count=0 then return False; end if;
      if not (Is_Command("challenge",1) or else Is_Command("keygen",2) or else Is_Command("make-policy",3)
        or else Is_Command("rotate-policy",3) or else Is_Command("make-request",4) or else Is_Command("sign-witness",4) or else Is_Command("sign-health-report",4) or else Is_Command("repair-ledger",5))
      then return False; end if;
      MC_Runtime.Initialize(S); if S/=OK then Result; return True; end if;
      if Is_Command("repair-ledger",5) then
         declare HF : MC_Protocol.Frame_Header; RF : MC_Requests.Request_Bytes;
            SG : MC_Signatures.Signature; WS : MC_Gate.Witness_Set;
         begin
            MC_Request_Files.Load(Argument(5),HF,RF,SG,WS,S);
            if S=OK then MC_Gate.Repair_Ledger(Argument(2),Argument(3),Argument(4),HF,RF,SG,WS,S); end if;
         end;
         Put_Line("ledger repair does not resolve host effects; explicit reconcile required"); Result; return True;
      elsif Is_Command("challenge",1) then
         MC_Clock.Read_Boot_ID(Boot,S); if S=OK then MC_Clock.Boottime_Milliseconds(Now,S); end if;
         if S=OK then MC_Clock.Realtime_Seconds(UTC,S); end if;
         if S=OK then
            Put_Line("boot=" & MC_Hex.Encode(Boot)); Put_Line("boottime-ms=" & MC_Numbers.Image(Now));
            Put_Line("realtime-seconds=" & MC_Numbers.Image(UTC));
            Put_Line("challenge_transport_must_be_authenticated=true");
         end if; Result; return True;
      elsif Is_Command("keygen",2) then
         MC_Keys.Generate(Argument(2),PK,S); if S=OK then Put_Line("public-key=" & MC_Hex.Encode(PK)); end if;
         Result; return True;
      elsif Is_Command("sign-health-report",4) then
         -- Administrative signing of explicit facts, not a sensor. Restrict the
         -- observer key to a qualified observer, separate from request authority.
         Load_Spec("cluster,node,resource,invocation,configuration,recovery-policy,boot,sequence,observed-ms,expires-ms,condition,config-valid,dependencies-ready,data-compatible,ownership-exclusive,business-healthy,maintenance,emergency-stop");
         declare
            HR : MC_Health_Report.Report; HB : MC_Health_Report.Frame;
            Domain : constant String:="MC-HEALTH-v1";
            Signed : Bytes(1..2+Domain'Length+256);
            Found : Boolean:=False;
            procedure Boolean_Field(Name : String; Value : out Boolean) is
            begin
               Value:=False; if S/=OK then return; end if;
               MC_Properties.Get(D,Name,V,S); if S/=OK then return; end if;
               if MC_Text.Image(V)="true" then Value:=True;
               elsif MC_Text.Image(V)/="false" then S:=Invalid_Input; end if;
            end;
         begin
            Field("cluster",HR.Cluster_ID); Field("node",HR.Node_ID); Field("resource",HR.Resource_ID);
            Field("invocation",HR.Invocation_ID); Field("configuration",HR.Configuration);
            Field("recovery-policy",HR.Recovery_Policy); Field("boot",HR.Stamp.Boot_ID);
            Number("sequence",HR.Stamp.Sequence); Number("observed-ms",HR.Stamp.Observed_At);
            Number("expires-ms",HR.Stamp.Expires_At);
            if S=OK then
               MC_Properties.Get(D,"condition",V,S);
               for K in MC_Health_Report.Condition loop
                  if MC_Text.Image(V)=MC_Health_Report.Condition'Image(K) then HR.Result:=K; Found:=True; end if;
               end loop;
               if not Found then S:=Invalid_Input; end if;
            end if;
            Boolean_Field("config-valid",HR.Config_Valid); Boolean_Field("dependencies-ready",HR.Dependencies_Ready);
            Boolean_Field("data-compatible",HR.Data_Compatible); Boolean_Field("ownership-exclusive",HR.Ownership_Exclusive);
            Boolean_Field("business-healthy",HR.Business_Healthy); Boolean_Field("maintenance",HR.Maintenance);
            Boolean_Field("emergency-stop",HR.Emergency_Stop);
            if S=OK and then not MC_Health_Report.Valid(HR) then S:=Invalid_Input; end if;
            if S=OK then
               HB:=MC_Health_Report.Encode(HR); MC_Codec.Put16(Signed,1,Domain'Length);
               for I in Domain'Range loop Signed(2+I):=Byte(Character'Pos(Domain(I))); end loop;
               Signed(3+Domain'Length..Signed'Last):=HB;
               MC_Keys.Sign(Argument(3),Signed,PK,Sig,S);
               if S=OK then MC_FS.Open_Root(Argument(4),Dir,S,Private_Only=>True); end if;
               if S=OK then MC_Atomic.Write(Dir,"health.bin",HB,False,S); end if;
               if S=OK then MC_Atomic.Write(Dir,"health.sig",Sig,False,S); end if;
               -- Interrupted publication yields signature mismatch; no reader
               -- consumes unauthenticated claims. Keep old evidence separately.
            end if;
         end;
         Put_Line("observed_by_this_tool=false scope_and_freshness_checked_by_receiver=true");
         Result; return True;
      elsif Is_Command("make-policy",3) or else Is_Command("rotate-policy",3) then
         Load_Spec("root,cluster,node,resource,epoch,fence,request-key,reservation-key,quiescence-key,health-key,compatibility-key,isolation-key,contract,serial,valid-until,max-lease-ms,max-witness-ms,allowed");
         Field("root",P.Root_ID); Field("cluster",P.Scope.Cluster_ID); Field("node",P.Scope.Node_ID); Field("resource",P.Scope.Resource_ID);
         Number("epoch",P.Scope.Membership_Epoch); Number("fence",P.Scope.Fence_Token); Field("request-key",P.Request_Key);
         Field("reservation-key",P.Observers(MC_Witness.Cluster_Reservation)); Field("quiescence-key",P.Observers(MC_Witness.Resource_Quiesced));
         Field("health-key",P.Observers(MC_Witness.Semantic_Health)); Field("compatibility-key",P.Observers(MC_Witness.Data_Backward_Compatible));
         Field("isolation-key",P.Observers(MC_Witness.Isolation_Confirmed)); Field("contract",P.Contract);
         Number("serial",P.Serial); Number("valid-until",P.Valid_Until); Number("max-lease-ms",P.Scope.Maximum_Local_Lease);
         Number("max-witness-ms",P.Maximum_Witness_Age);
         if S=OK then
            MC_Properties.Get(D,"allowed",V,S);
            declare Text : constant String:=MC_Text.Image(V); Start : Positive:=Text'First; Found : Boolean; begin
               for I in Text'First..Text'Last+1 loop
                  if I=Text'Last+1 or else Text(I)=',' then
                     if I=Start then S:=Invalid_Input; exit; end if; Found:=False;
                     for A in MC_Requests.Requested_Action loop
                        if Text(Start..I-1)=Action_Name(A) then
                           if P.Scope.Allowed(Header_Kind(A)) then S:=Conflict; exit; end if;
                           P.Scope.Allowed(Header_Kind(A)):=True; Found:=True;
                        end if;
                     end loop;
                     if not Found then S:=Invalid_Input; exit; end if; Start:=I+1;
                  end if;
               end loop;
            end;
         end if;
         if S=OK and then P.Contract/=MC_Contract_Profile.Fingerprint then S:=Unsupported; end if;
         if S=OK then Frame:=MC_Site_Policy.Encode(P); MC_Site_Policy.Decode(Frame,Decoded,S); end if;
         if S=OK then MC_FS.Open_Root(Argument(3),Dir,S,Private_Only=>True); end if;
         if S=OK then MC_FS.Open_Locked(Dir,"policy.lock",Lock,S,Create_If_Missing=>Argument(1)="make-policy"); end if;
         if S=OK and then Argument(1)="rotate-policy" then
            MC_Site_Policy.Load(Dir,Old,Digest_Of_Policy,S);
            if S=OK and then (P.Serial<=Old.Serial or else P.Root_ID/=Old.Root_ID
              or else P.Scope.Cluster_ID/=Old.Scope.Cluster_ID or else P.Scope.Node_ID/=Old.Scope.Node_ID
              or else P.Scope.Membership_Epoch<Old.Scope.Membership_Epoch or else P.Scope.Fence_Token<Old.Scope.Fence_Token)
            then S:=Stale; end if;
         end if;
         if S=OK then MC_Atomic.Write(Dir,"policy.bin",Frame,Argument(1)="make-policy",S); end if;
         Result; return True;
      elsif Is_Command("make-request",4) then
         Load_Spec("action,request,cluster,node,resource,boot,epoch,fence,sequence,deadline-ms,transaction,plan,contract,policy-serial,base-generation,stage-set,evidence");
         Field("request",H.Request_ID); Field("cluster",H.Cluster_ID); Field("node",H.Node_ID); Field("resource",H.Resource_ID);
         Field("boot",H.Boot_ID); Number("epoch",H.Membership_Epoch); Number("fence",H.Fence_Token);
         Number("sequence",H.Sequence_Number); Number("deadline-ms",H.Deadline); Field("transaction",R.Transaction_ID);
         Field("plan",R.Plan_Digest); Field("contract",R.Contract_Digest); Number("policy-serial",R.Expected_Revision);
         Number("base-generation",R.Base_Generation); Field("stage-set",R.Stage_Set_Digest); Field("evidence",R.Evidence_Digest);
         if S=OK then
            MC_Properties.Get(D,"action",V,S);
            declare Found : Boolean:=False; begin
               for A in MC_Requests.Requested_Action loop if MC_Text.Image(V)=Action_Name(A) then R.Action:=A; Found:=True; end if; end loop;
               if not Found then S:=Invalid_Input; end if;
            end;
         end if;
         if S=OK then
            declare
               Body_Data : constant MC_Requests.Request_Bytes:=MC_Requests.Encode(R);
               Check : MC_Requests.Request; Envelope : MC_Request_Files.Envelope;
               Signed : Bytes(1..176):=(others=>0); Domain : constant String:="MCP2-SIGNED-V2";
            begin
               MC_Requests.Decode(Body_Data,Check,S);
               H.Kind:=Header_Kind(R.Action); H.Body_Length:=Body_Data'Length; H.Body_Digest:=MC_SHA256.Hash(Body_Data);
               if not MC_Protocol.Valid_Identity(H) then S:=Invalid_Input; end if;
               for I in Domain'Range loop Signed(I):=Byte(Character'Pos(Domain(I))); end loop;
               Signed(17..176):=MC_Protocol.Encode(H);
               if S=OK then MC_Keys.Sign(Argument(3),Signed,PK,Sig,S); end if;
               if S=OK then
                  Envelope(1..160):=MC_Protocol.Encode(H); Envelope(161..352):=Body_Data; Envelope(353..416):=Sig;
                  MC_FS.Open_Root(Argument(4),Dir,S,Private_Only=>True);
                  if S=OK then MC_Atomic.Write(Dir,"envelope.bin",Envelope,True,S); end if;
               end if;
            end;
         end if;
         Result; return True;
      else
         -- This tool signs explicitly provided facts. It DOES NOT observe a cluster.
         -- Never grant access to these signing keys to a workload/request sender.
         Load_Spec("kind,cluster,node,root,transaction,boot,plan,contract,epoch,fence,issued-ms,expires-ms");
         Field("cluster",W.Cluster_ID); Field("node",W.Node_ID); Field("root",W.Root_ID); Field("transaction",W.Transaction_ID);
         Field("boot",W.Boot_ID); Field("plan",W.Plan); Field("contract",W.Contract);
         Number("epoch",W.Epoch); Number("fence",W.Token); Number("issued-ms",W.Issued); Number("expires-ms",W.Expires);
         if S=OK then
            MC_Properties.Get(D,"kind",V,S);
            declare N : Counter; begin
               MC_Numbers.Parse(MC_Text.Image(V),N,S);
               if S=OK and then N<=MC_Witness.Fact'Pos(MC_Witness.Fact'Last) then W.Kind:=MC_Witness.Fact'Val(N); else S:=Invalid_Input; end if;
            end;
         end if;
         if S=OK then
            declare
               WF : constant MC_Witness.Frame:=MC_Witness.Encode(W); Checked : MC_Witness.Statement;
               Domain : constant String:="MC-WITNESS-v2"; Signed : Bytes(1..2+Domain'Length+224); File_Data : Bytes(1..288);
            begin
               MC_Witness.Decode(WF,Checked,S); MC_Codec.Put16(Signed,1,Domain'Length);
               for I in Domain'Range loop Signed(2+I):=Byte(Character'Pos(Domain(I))); end loop;
               Signed(3+Domain'Length..Signed'Last):=WF;
               if S=OK then MC_Keys.Sign(Argument(3),Signed,PK,Sig,S); end if;
               if S=OK then
                  File_Data(1..224):=WF; File_Data(225..288):=Sig;
                  MC_FS.Open_Root(Argument(4),Dir,S,Private_Only=>True);
                  if S=OK then MC_Atomic.Write(Dir,"witness-" & MC_Numbers.Image(Counter(MC_Witness.Fact'Pos(W.Kind))) & ".bin",File_Data,False,S); end if;
               end if;
            end;
         end if;
         Result; return True;
      end if;
   exception when others=>MC_FS.Close(Lock); MC_FS.Close(Dir); Put_Line(Standard_Error,"administrative operation failed"); Set_Exit_Status(Failure); return True;
   end Handle;
end MC_Admin;
