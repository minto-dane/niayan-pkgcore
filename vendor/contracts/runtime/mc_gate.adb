-- SPDX-License-Identifier: BSD-3-Clause
with MC_Contract_Profile; with MC_Control; with MC_Control_IO;
with MC_Clock; with MC_Atomic; with MC_Ingress; with MC_Replay; with MC_SHA256;
with MC_Request_Replay; with MC_Log_Format; with MC_Hex; with MC_Authentic; with MC_Store;
package body MC_Gate with SPARK_Mode => Off is
   use type MC_Replay.Decision; use type MC_Requests.Requested_Action;
   use type MC_Witness.Fact;
   Begun : constant:=200; Known_OK : constant:=201; Known_Failure : constant:=202;
   Unknown_Outcome : constant:=203;
   procedure Read_Previous(S : in out Session; Window : out MC_Replay.Window;
      Pending : out Boolean; Serial : out Counter; Status : out Outcome) is
      E : MC_Log_Format.Log_Entry; R : MC_Request_Replay.State;
   begin
      Window := (others => <>); Pending := False; Serial := 0;
      Status := Corrupt;
      if MC_Log.Length(S.Journal) = 0 then return; end if;
      for I in 1 .. MC_Log.Length(S.Journal) loop
         MC_Log.Read(S.Journal,I,E,Status);
         if Status = OK then MC_Request_Replay.Consume(R,E,Status); end if;
         if Status /= OK then return; end if;
      end loop;
      Window := R.Window; Pending := R.Pending; Serial := R.Serial; Status := OK;
   end Read_Previous;
   procedure Begin_Request(Policy_Directory, Ledger_Directory : String;
      Header, Body_Data : Bytes; Signature : MC_Signatures.Signature;
      Witnesses : Witness_Set; S : in out Session; Mode : out Admission; Status : out Outcome) is
      Before, Candidate : MC_Replay.Window; Decision : MC_Replay.Decision;
      Pending : Boolean; Now, UTC, Serial : Counter; Boot : Identity;
      E : MC_Log_Format.Log_Entry; Envelope : Bytes(1..416); Prior : Bytes(1..416); Used : Natural;
      Prior_Request : MC_Requests.Request;
   begin
      Mode:=Unknown_Retry; Status:=Invalid_Input;
      if S.Admitted or else Header'Length/=160 or else Body_Data'Length/=MC_Requests.Body_Size then return; end if;
      MC_FS.Open_Root(Policy_Directory,S.Policy_Root,Status,Private_Only=>True); if Status/=OK then return; end if;
      MC_Site_Policy.Load(S.Policy_Root,S.Policy,S.Policy_Digest,Status);
      if Status=OK and then S.Policy.Contract/=MC_Contract_Profile.Fingerprint then Status:=Unsupported; end if;
      if Status=OK then MC_Clock.Realtime_Seconds(UTC,Status); end if;
      if Status=OK and then UTC>=S.Policy.Valid_Until then Status:=Stale; end if;
      if Status=OK then MC_Clock.Read_Boot_ID(Boot,Status); end if;
      if Status=OK then S.Policy.Scope.Boot_ID:=Boot; MC_Clock.Boottime_Milliseconds(Now,Status); end if;
      if Status=OK then MC_FS.Open_Root(Ledger_Directory,S.Ledger_Root,Status,Private_Only=>True); end if;
      if Status=OK then MC_Log.Open(S.Ledger_Root,"requests.log",S.Policy.Root_ID,S.Journal,Status,Create_If_Missing=>False); end if;
      if Status/=OK then Close(S); return; end if;
      Read_Previous(S,Before,Pending,Serial,Status); if Status/=OK then Close(S); return; end if;
      if S.Policy.Serial<Serial then Status:=Stale; Close(S); return; end if;
      MC_Ingress.Check_Request(Header,Body_Data,Signature,S.Policy.Request_Key,S.Policy.Scope,
        S.Policy.Contract,Now,Before,Candidate,S.Content,Decision,Status);
      if Status/=OK then Close(S); return; end if;
      if S.Content.Expected_Revision/=S.Policy.Serial then Status:=Stale; Close(S); return; end if;
      MC_Protocol.Decode(Header,S.Header,Status); if Status/=OK then Close(S); return; end if;
      if MC_Log.Length(S.Journal)>0 then
         MC_Log.Read(S.Journal,MC_Log.Length(S.Journal),E,Status); if Status/=OK then Close(S); return; end if;
         S.Last_Result:=(if Pending then Indeterminate else E.Result);
      end if;
      if Decision=MC_Replay.Exact_Retry then
         Mode:=(if Pending then Unknown_Retry else Known_Retry); Status:=OK; return;
      end if;
      if Decision/=MC_Replay.Fresh then Status:=Denied; Close(S); return; end if;
      if Pending then
         MC_Atomic.Read(S.Ledger_Root,"request-" & MC_Hex.Encode(Before.Request_ID) & ".bin",Prior,Used,Status);
         if Status/=OK or else Used/=416 or else MC_SHA256.Hash(Prior(1..160))/=Before.Request_Digest
         then Status:=Corrupt; Close(S); return; end if;
         MC_Requests.Decode(Prior(161..352),Prior_Request,Status);
         if Status/=OK or else S.Content.Action not in MC_Requests.Recover | MC_Requests.Restore | MC_Requests.Reconcile | MC_Requests.Repair
           or else S.Content.Transaction_ID/=Prior_Request.Transaction_ID
           or else S.Content.Plan_Digest/=Prior_Request.Plan_Digest
         then Status:=Conflict; Close(S); return; end if;
      end if;
      -- New work retains bounded room for completion, one recovery request and
      -- tail-repair records. Recovery consumes part of this reserve, never space
      -- promised to an already admitted terminal record. Rotation is a separate
      -- authenticated maintenance protocol, not deletion on capacity exhaustion.
      declare Needed : constant Counter :=
        (if S.Content.Action in MC_Requests.Recover | MC_Requests.Restore |
            MC_Requests.Reconcile | MC_Requests.Repair then 4 else 8); begin
         if not MC_Log.Can_Append(S.Journal,Needed) then
            Status:=Exhausted; Close(S); return;
         end if;
      end;
      Envelope(1..160):=Header; Envelope(161..352):=Body_Data; Envelope(353..416):=Signature;
      MC_Atomic.Write(S.Ledger_Root,"request-" & MC_Hex.Encode(S.Header.Request_ID) & ".bin",Envelope,True,Status);
      if Status=Conflict then
         MC_Atomic.Read(S.Ledger_Root,"request-" & MC_Hex.Encode(S.Header.Request_ID) & ".bin",Prior,Used,Status);
         if Status=OK and then (Used/=416 or else Prior/=Envelope) then Status:=Conflict; end if;
      end if;
      if Status/=OK then Close(S); return; end if;
      E.Kind:=Begun; E.Result:=OK; E.Root_ID:=S.Policy.Root_ID; E.Operation_ID:=S.Header.Request_ID;
      E.Epoch:=S.Header.Membership_Epoch; E.Token:=S.Header.Fence_Token;
      E.Index:=S.Header.Sequence_Number; E.Object:=MC_SHA256.Hash(Header); E.Generation:=S.Policy.Serial;
      MC_Log.Append(S.Journal,E,Status); if Status/=OK then Close(S); return; end if;
      S.Witnesses:=Witnesses; S.Admitted:=True; S.Pending:=True; Mode:=New_Request;
   exception when others => Close(S); Status:=Indeterminate;
   end Begin_Request;
   procedure Require_Fact(S : Session; F : MC_Witness.Fact; Now : Counter;
                           Receipt : Digest; Status : out Outcome) is
      Actual, Expected : MC_Witness.Statement;
   begin
      Status:=Denied; if not S.Witnesses.Present(F) then return; end if;
      MC_Authentic.Verify("MC-WITNESS-v2",S.Witnesses.Statements(F),S.Witnesses.Signatures(F),S.Policy.Observers(F),Status);
      if Status/=OK then return; end if;
      MC_Witness.Decode(S.Witnesses.Statements(F),Actual,Status); if Status/=OK then return; end if;
      Expected.Kind:=F; Expected.Cluster_ID:=S.Header.Cluster_ID; Expected.Node_ID:=S.Header.Node_ID;
      Expected.Root_ID:=S.Policy.Root_ID; Expected.Transaction_ID:=S.Content.Transaction_ID;
      Expected.Boot_ID:=S.Header.Boot_ID; Expected.Plan:=S.Content.Plan_Digest;
      Expected.Contract:=S.Policy.Contract; Expected.Epoch:=S.Header.Membership_Epoch; Expected.Token:=S.Header.Fence_Token;
      if not MC_Witness.Matches(Actual,Expected,Now,S.Policy.Maximum_Witness_Age) then Status:=Stale; return; end if;
      if Receipt/=Zero_Digest and then MC_SHA256.Hash(S.Witnesses.Statements(F))/=Receipt then Status:=Denied; end if;
   end Require_Fact;
   procedure Repair_Ledger(Policy_Directory, Ledger_Directory, Store_Directory : String;
      Header, Body_Data : Bytes; Signature : MC_Signatures.Signature;
      Witnesses : Witness_Set; Status : out Outcome) is
      S : Session; Store : MC_Store.Store; Before,Candidate : MC_Replay.Window;
      Decision : MC_Replay.Decision; Pending : Boolean; Serial,Now,UTC : Counter; Boot : Identity;
      Prior,Envelope : Bytes(1..416); Recovery_Record : Bytes(1..480):=(others=>0);
      Used,Tail_Length : Natural; Tail : Bytes(1..256); Tail_Digest : Digest;
      Prior_Request : MC_Requests.Request; E : MC_Log_Format.Log_Entry; Other : Outcome;
      procedure Done is
      begin MC_Store.Close(Store); Close(S); end;
   begin
      Status:=Invalid_Input; if Header'Length/=160 or else Body_Data'Length/=MC_Requests.Body_Size then return; end if;
      MC_FS.Open_Root(Policy_Directory,S.Policy_Root,Status,Private_Only=>True); if Status/=OK then Done; return; end if;
      MC_Site_Policy.Load(S.Policy_Root,S.Policy,S.Policy_Digest,Status);
      if Status=OK and then S.Policy.Contract/=MC_Contract_Profile.Fingerprint then Status:=Unsupported; end if; if Status/=OK then Done; return; end if;
      MC_Clock.Realtime_Seconds(UTC,Status); if Status/=OK then Done; return; end if;
      if UTC>=S.Policy.Valid_Until then Status:=Stale; Done; return; end if;
      MC_Clock.Read_Boot_ID(Boot,Status); if Status/=OK then Done; return; end if;
      S.Policy.Scope.Boot_ID:=Boot; MC_Clock.Boottime_Milliseconds(Now,Status); if Status/=OK then Done; return; end if;
      MC_FS.Open_Root(Ledger_Directory,S.Ledger_Root,Status,Private_Only=>True); if Status/=OK then Done; return; end if;
      MC_Log.Open(S.Ledger_Root,"requests.log",S.Policy.Root_ID,S.Journal,Status,Create_If_Missing=>False);
      if Status/=Indeterminate or else not MC_Log.Has_Torn_Tail(S.Journal) then
         if Status=OK then Status:=Conflict; end if; Done; return;
      end if;
      Read_Previous(S,Before,Pending,Serial,Status); if Status/=OK then Done; return; end if;
      if S.Policy.Serial<Serial then Status:=Stale; Done; return; end if;
      MC_Ingress.Check_Request(Header,Body_Data,Signature,S.Policy.Request_Key,S.Policy.Scope,S.Policy.Contract,
         Now,Before,Candidate,S.Content,Decision,Status); if Status/=OK then Done; return; end if;
      if Decision/=MC_Replay.Fresh or else S.Content.Action/=MC_Requests.Repair
        or else S.Content.Expected_Revision/=S.Policy.Serial then Status:=Denied; Done; return; end if;
      MC_Protocol.Decode(Header,S.Header,Status); if Status/=OK then Done; return; end if;
      S.Witnesses:=Witnesses;
      Require_Fact(S,MC_Witness.Cluster_Reservation,Now,Zero_Digest,Status); if Status/=OK then Done; return; end if;
      Require_Fact(S,MC_Witness.Isolation_Confirmed,Now,Zero_Digest,Status); if Status/=OK then Done; return; end if;
      if Pending then
         MC_Atomic.Read(S.Ledger_Root,"request-" & MC_Hex.Encode(Before.Request_ID) & ".bin",Prior,Used,Status);
         if Status/=OK or else Used/=416 or else MC_SHA256.Hash(Prior(1..160))/=Before.Request_Digest
         then Status:=Corrupt; Done; return; end if;
         MC_Requests.Decode(Prior(161..352),Prior_Request,Status);
         if Status/=OK or else Prior_Request.Transaction_ID/=S.Content.Transaction_ID
           or else Prior_Request.Plan_Digest/=S.Content.Plan_Digest then Status:=Conflict; Done; return; end if;
      end if;
      if not MC_Log.Can_Append(S.Journal,2,After_Tail_Repair=>True) then
         Status:=Exhausted; Done; return;
      end if;
      MC_Log.Export_Tail(S.Journal,Tail,Tail_Length,Status); if Status/=OK then Done; return; end if;
      MC_Store.Open(Store_Directory,Store,Status); if Status/=OK then Done; return; end if;
      MC_Store.Put(Store,Tail(1..Tail_Length),Tail_Digest,Status); if Status/=OK then Done; return; end if;
      Envelope(1..160):=Header; Envelope(161..352):=Body_Data; Envelope(353..416):=Signature;
      Recovery_Record(1..416):=Envelope; Recovery_Record(417..448):=Tail_Digest;
      Recovery_Record(449..480):=MC_Log.Head(S.Journal);
      MC_Atomic.Write(S.Ledger_Root,"repair-" & MC_Hex.Encode(S.Header.Request_ID) & ".bin",Recovery_Record,True,Status);
      if Status=Conflict then
         declare Saved : Bytes(1..480); begin
            MC_Atomic.Read(S.Ledger_Root,"repair-" & MC_Hex.Encode(S.Header.Request_ID) & ".bin",Saved,Used,Status);
            if Status=OK and then (Used/=480 or else Saved/=Recovery_Record) then Status:=Conflict; end if;
         end;
      end if;
      if Status/=OK then Done; return; end if;
      MC_Atomic.Write(S.Ledger_Root,"request-" & MC_Hex.Encode(S.Header.Request_ID) & ".bin",Envelope,True,Status);
      if Status=Conflict then
         MC_Atomic.Read(S.Ledger_Root,"request-" & MC_Hex.Encode(S.Header.Request_ID) & ".bin",Prior,Used,Status);
         if Status=OK and then (Used/=416 or else Prior/=Envelope) then Status:=Conflict; end if;
      end if;
      if Status/=OK then Done; return; end if;
      -- Recheck policy/time immediately before truncation; never fall back to an
      -- expired or rotated key merely because a recovery record was created.
      MC_Site_Policy.Load(S.Policy_Root,S.Policy,Tail_Digest,Status);
      if Status/=OK or else Tail_Digest/=S.Policy_Digest then Status:=Stale; Done; return; end if;
      MC_Clock.Boottime_Milliseconds(Now,Status); if Status/=OK then Done; return; end if;
      if Now>=S.Header.Deadline then Status:=Stale; Done; return; end if;
      Tail_Digest:=Recovery_Record(417..448);
      MC_Control_IO.Check(S.Policy_Root,S.Policy.Root_ID,MC_Control.Repair_Records,Status);
      if Status/=OK then Done; return; end if;
      MC_Log.Repair_Tail(S.Journal,Tail_Digest,Status); if Status/=OK then Done; return; end if;
      E.Kind:=Begun; E.Result:=OK; E.Root_ID:=S.Policy.Root_ID; E.Operation_ID:=S.Header.Request_ID;
      E.Epoch:=S.Header.Membership_Epoch; E.Token:=S.Header.Fence_Token; E.Index:=S.Header.Sequence_Number;
      E.Object:=MC_SHA256.Hash(Header); E.Generation:=S.Policy.Serial;
      MC_Log.Append(S.Journal,E,Status);
      if Status=OK then E.Kind:=Unknown_Outcome; E.Result:=Indeterminate; MC_Log.Append(S.Journal,E,Status); end if;
      Other:=Status; Done; Status:=Other;
   exception when others=>Done; Status:=Indeterminate;
   end Repair_Ledger;
   procedure Check(S : in out Session; Root_ID, Transaction_ID : Identity;
      Plan, Evidence : Digest; Origin_Epoch, Origin_Fence : Counter;
      Phase : String; Status : out Outcome) is
      Current : MC_Site_Policy.Policy; D : Digest; Now, UTC : Counter; Boot : Identity;
      Is_Recovery : constant Boolean:=S.Content.Action in MC_Requests.Recover | MC_Requests.Restore | MC_Requests.Reconcile | MC_Requests.Repair | MC_Requests.Commit;
   begin
      Status:=Denied;
      if not S.Admitted or else not S.Pending or else Root_ID/=S.Policy.Root_ID
        or else Transaction_ID/=S.Content.Transaction_ID or else Plan/=S.Content.Plan_Digest then return; end if;
      MC_Site_Policy.Load(S.Policy_Root,Current,D,Status); if Status/=OK then return; end if;
      if D/=S.Policy_Digest then Status:=Stale; return; end if;
      MC_Clock.Realtime_Seconds(UTC,Status); if Status/=OK then return; end if;
      if UTC>=Current.Valid_Until then Status:=Stale; return; end if;
      MC_Clock.Read_Boot_ID(Boot,Status); if Status/=OK then return; end if;
      MC_Clock.Boottime_Milliseconds(Now,Status); if Status/=OK then return; end if;
      if Boot/=S.Header.Boot_ID or else Now>=S.Header.Deadline then Status:=Stale; return; end if;
      if Is_Recovery then
         if S.Header.Membership_Epoch<Origin_Epoch or else S.Header.Fence_Token<Origin_Fence then Status:=Stale; return; end if;
      elsif S.Header.Membership_Epoch/=Origin_Epoch or else S.Header.Fence_Token/=Origin_Fence then Status:=Stale; return; end if;
      if Phase="prepare" or else Phase="capture" then
         if S.Content.Action/=MC_Requests.Prepare then Status:=Denied; return; end if;
      elsif Phase="restore" then
         if S.Content.Action/=MC_Requests.Restore then Status:=Denied; return; end if;
      elsif Phase="repair-journal" or else Phase="repair-healing-journal" then
         if S.Content.Action/=MC_Requests.Repair then Status:=Denied; return; end if;
      elsif Phase="finish-terminal" then
         if S.Content.Action/=MC_Requests.Reconcile then Status:=Denied; return; end if;
      elsif Phase="commit" then
         if S.Content.Action/=MC_Requests.Commit then Status:=Denied; return; end if;
      elsif Phase="apply" then
         if S.Content.Action not in MC_Requests.Apply | MC_Requests.Recover then Status:=Denied; return; end if;
      elsif Phase="file-effect" or else Phase="publish-file" then
         if S.Content.Action not in MC_Requests.Apply | MC_Requests.Recover | MC_Requests.Restore then Status:=Denied; return; end if;
      elsif Phase="service-stop" or else Phase="service-start" or else Phase="service-restart"
        or else Phase="service-reload" or else Phase="cluster-drain" or else Phase="cluster-rejoin" then
         if S.Content.Action/=MC_Requests.Apply then Status:=Denied; return; end if;
      elsif Phase="observe-effect" then
         if S.Content.Action not in MC_Requests.Apply | MC_Requests.Reconcile then Status:=Denied; return; end if;
      else Status:=Unsupported; return; end if;
      declare
         Action : MC_Control.Operation := MC_Control.Change_Files;
      begin
         if Phase in "observe-effect" | "finish-terminal" then Action := MC_Control.Inspect;
         elsif Phase in "service-stop" | "cluster-drain" then Action := MC_Control.Contain;
         elsif Phase in "repair-journal" | "repair-healing-journal" then Action := MC_Control.Repair_Records;
         elsif Phase = "commit" then Action := MC_Control.Accept_State;
         elsif Phase = "cluster-rejoin" then Action := MC_Control.Join_Cluster;
         elsif Phase in "service-start" | "service-restart" | "service-reload" then Action := MC_Control.Activate_Service;
         elsif S.Content.Action = MC_Requests.Restore then Action := MC_Control.Restore_State;
         end if;
         MC_Control_IO.Check(S.Policy_Root,S.Policy.Root_ID,Action,Status);
         if Status/=OK then return; end if;
      end;
      Require_Fact(S,MC_Witness.Cluster_Reservation,Now,Zero_Digest,Status); if Status/=OK then return; end if;
      if Phase="repair-healing-journal" then
         Require_Fact(S,MC_Witness.Isolation_Confirmed,Now,Zero_Digest,Status); if Status/=OK then return; end if;
         Require_Fact(S,MC_Witness.Resource_Quiesced,Now,Zero_Digest,Status);
      elsif Phase="commit" or else Phase="cluster-rejoin" then
         if Evidence=Zero_Digest or else Evidence/=S.Content.Evidence_Digest then Status:=Denied; return; end if;
         Require_Fact(S,MC_Witness.Semantic_Health,Now,Evidence,Status);
      elsif S.Content.Action=MC_Requests.Restore then
         Require_Fact(S,MC_Witness.Resource_Quiesced,Now,Zero_Digest,Status); if Status/=OK then return; end if;
         if S.Content.Evidence_Digest=Zero_Digest or else (Evidence/=Zero_Digest and then Evidence/=S.Content.Evidence_Digest)
         then Status:=Denied; return; end if;
         Require_Fact(S,MC_Witness.Data_Backward_Compatible,Now,S.Content.Evidence_Digest,Status);
      elsif Phase not in "prepare" | "capture" | "cluster-drain" | "service-stop" | "observe-effect" then
         Require_Fact(S,MC_Witness.Resource_Quiesced,Now,Zero_Digest,Status);
      end if;
   end Check;
   procedure Finish(S : in out Session; Result : Outcome; Status : out Outcome) is
      E : MC_Log_Format.Log_Entry;
   begin
      Status:=Invalid_Input; if not S.Admitted or else not S.Pending then return; end if;
      E.Kind:=(if Result=OK then Known_OK elsif Result=Indeterminate then Unknown_Outcome else Known_Failure);
      E.Root_ID:=S.Policy.Root_ID; E.Operation_ID:=S.Header.Request_ID;
      E.Epoch:=S.Header.Membership_Epoch; E.Token:=S.Header.Fence_Token; E.Index:=S.Header.Sequence_Number;
      E.Object:=MC_SHA256.Hash(MC_Protocol.Encode(S.Header)); E.Generation:=S.Policy.Serial; E.Result:=Result;
      MC_Log.Append(S.Journal,E,Status); S.Admitted:=False;
      if Status=OK then S.Last_Result:=Result; end if;
   end Finish;
   procedure Refresh_Witnesses(S : in out Session; W : Witness_Set) is
   begin S.Witnesses:=W; end;
   function Health_Observer_Allowed(S : Session; Key : MC_Signatures.Public_Key) return Boolean is
     (S.Admitted and then Key=S.Policy.Observers(MC_Witness.Semantic_Health)
       and then Key/=S.Policy.Request_Key and then not Is_Zero(Key));
   function Deadline(S : Session) return Counter is (S.Header.Deadline);
   function Receipt_Result(S : Session) return Outcome is (S.Last_Result);
   function Request(S : Session) return MC_Requests.Request is (S.Content);
   procedure Close(S : in out Session) is
   begin MC_Log.Close(S.Journal); MC_FS.Close(S.Ledger_Root); MC_FS.Close(S.Policy_Root); S.Admitted:=False; S.Pending:=False; end;
end MC_Gate;
