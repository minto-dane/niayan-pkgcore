-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation;
with MC_FS; with MC_Atomic; with MC_Hex; with MC_SHA256; with MC_Log_Format;
with Pkg_Root_State; with Pkg_File_Plan;
package body Pkg_Recovery_Audit with SPARK_Mode => Off is
   use type MC_FS.Entry_Kind;
   use type MC_FS.Entry_Info;
   use type Pkg_File_Replay.Direction;
   procedure Inspect (State_Path, Store_Path : String; Expected_Plan : Digest;
                      R : out Report; Status : out Outcome) is
      State_Dir, Store_Dir : MC_FS.Root;
      Journal : MC_FS.File;
      RS : Pkg_Root_State.State;
      State_Bytes, State_After : Pkg_Root_State.Frame;
      type Plan_Access is access Pkg_File_Plan.Plan;
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation(Pkg_File_Plan.Plan,Plan_Access);
      procedure Free is new Ada.Unchecked_Deallocation(Bytes,Buffer_Access);
      P : Plan_Access := null;
      Payload : Buffer_Access := null;
      Pin : Bytes (1 .. 33);
      Frame : MC_Log_Format.Frame;
      E : MC_Log_Format.Log_Entry;
      Binding : Pkg_File_Replay.Binding;
      V : Pkg_File_Replay.View;
      Initial, Final : MC_FS.Entry_Info;
      Count, Whole : Counter := 0;
      Used : Natural;
      procedure Close_All is
      begin MC_FS.Close (Journal); MC_FS.Close (Store_Dir); MC_FS.Close (State_Dir); Free(P); Free(Payload); end;
      procedure Fail (Why : Finding; Code : Outcome) is
      begin R.Result := Why; Status := Code; Close_All; end;
      procedure Read_Present (Dir : MC_FS.Root; Name : String; B : out Bytes;
         N : out Natural; Missing, Invalid : Finding) is
         I : MC_FS.Entry_Info;
      begin
         B := (others => 0); N := 0;
         MC_FS.Stat (Dir,Name,I,Status);
         if Status /= OK then R.Result := Read_Failure; return; end if;
         if I.Kind = MC_FS.Absent then R.Result := Missing; Status := Corrupt; return; end if;
         if I.Kind /= MC_FS.Regular then R.Result := Invalid; Status := Corrupt; return; end if;
         MC_Atomic.Read (Dir,Name,B,N,Status);
         if Status /= OK then R.Result := Invalid; end if;
      end Read_Present;
   begin
      R := (others => <>); Status := Invalid_Input;
      if Expected_Plan = Zero_Digest then return; end if;
      P:=new Pkg_File_Plan.Plan;
      Payload:=new Bytes(1..Pkg_File_Plan.Max_Plan_Bytes);
      R.Plan_Digest := Expected_Plan;
      MC_FS.Open_Root (State_Path,State_Dir,Status,Private_Only => True);
      if Status /= OK then Fail (Read_Failure,Status); return; end if;
      MC_FS.Open_Root (Store_Path,Store_Dir,Status,Private_Only => True);
      if Status /= OK then Fail (Read_Failure,Status); return; end if;
      Read_Present (State_Dir,"root.state",State_Bytes,Used,Missing_State,Invalid_State);
      if Status /= OK then Close_All; return; end if;
      Pkg_Root_State.Decode (State_Bytes (1 .. Used),RS,Status);
      if Status /= OK then Fail (Invalid_State,Status); return; end if;
      R.Root_ID := RS.Root_ID; R.Root_Generation := RS.Generation;
      declare H : constant String := MC_Hex.Encode (Expected_Plan); begin
         Read_Present (Store_Dir,"objects/" & H(1..2) & "/" & H(3..64),
                       Payload.all,Used,Missing_Plan,Invalid_Plan);
      end;
      if Status /= OK then Close_All; return; end if;
      if MC_SHA256.Hash (Payload (1 .. Used)) /= Expected_Plan then
         Fail (Invalid_Plan,Corrupt); return;
      end if;
      Pkg_File_Plan.Decode (Payload (1 .. Used),P.all,Status);
      if Status /= OK then Fail (Invalid_Plan,Status); return; end if;
      R.Transaction_ID := P.Transaction_ID;
      if RS.Root_ID /= P.Root_ID or else
        (RS.Active_Transaction /= Zero_Identity and then
          (RS.Active_Transaction /= P.Transaction_ID or else RS.Active_Plan /= Expected_Plan))
      then Fail (State_Log_Disagreement,Conflict); return; end if;
      Read_Present (Store_Dir,"pins/" & MC_Hex.Encode (P.Transaction_ID),Pin,Used,Missing_Pin,Invalid_Pin);
      if Status /= OK then Close_All; return; end if;
      if Used /= 32 or else Pin (1..32) /= Expected_Plan then Fail (Invalid_Pin,Corrupt); return; end if;
      declare Name : constant String := "tx-" & MC_Hex.Encode (P.Transaction_ID) & ".log"; begin
         MC_FS.Stat (State_Dir,Name,Initial,Status);
         if Status /= OK then Fail (Read_Failure,Status); return; end if;
         if Initial.Kind = MC_FS.Absent then Fail (Missing_Journal,Corrupt); return; end if;
         if Initial.Kind /= MC_FS.Regular then Fail (Bad_Record,Corrupt); return; end if;
         MC_FS.Open_Read (State_Dir,Name,Journal,Status);
      end;
      if Status /= OK then Fail (Read_Failure,Status); return; end if;
      MC_FS.Info (Journal,Final,Status);
      if Status /= OK then Fail (Read_Failure,Status); return; end if;
      if Initial /= Final then Fail (Concurrent_Change,Indeterminate); return; end if;
      Whole := Initial.Size / MC_Log_Format.Record_Size;
      if Whole > 1_048_576 then Fail (Limit_Exceeded,Exhausted); return; end if;
      R.Tail_Bytes := Natural (Initial.Size mod MC_Log_Format.Record_Size);
      if Whole = 0 and then R.Tail_Bytes = 0 then Fail (Empty_Journal,Corrupt); return; end if;
      Binding := (Root_ID => P.Root_ID, Transaction_ID => P.Transaction_ID,
        Plan_Digest => Expected_Plan, Epoch => P.Epoch, Fence => P.Fence,
        Target_Generation => P.Target_Generation, Changes => P.Count);
      for I in 1 .. Whole loop
         MC_FS.Read_At (Journal,(I-1)*MC_Log_Format.Record_Size,Frame,Used,Status);
         R.Bad_Record_Number := I;
         if Status /= OK or else Used /= Frame'Length then Fail (Bad_Record,Corrupt); return; end if;
         MC_Log_Format.Decode (Frame,E,Status);
         if Status /= OK then Fail (Bad_Record,Status); return; end if;
         Pkg_File_Replay.Consume (Binding,E,V,Status);
         if Status /= OK then Fail (Bad_Record,Status); return; end if;
         Count := I; R.Complete_Records := Count;
         R.Log_State := V; R.Journal_Head := V.Last_Digest;
      end loop;
      R.Bad_Record_Number := 0; R.Complete_Records := Count;
      R.Log_State := V; R.Journal_Head := V.Last_Digest;
      if R.Tail_Bytes /= 0 then
         MC_FS.Read_At (Journal,Whole*MC_Log_Format.Record_Size,Frame,Used,Status);
         if Status /= OK or else Used /= R.Tail_Bytes then Fail (Concurrent_Change,Indeterminate); return; end if;
         R.Tail_Digest := MC_SHA256.Hash (Frame(1..Used));
      end if;
      MC_FS.Info (Journal,Final,Status);
      if Status /= OK or else Initial /= Final then Fail (Concurrent_Change,Indeterminate); return; end if;
      Read_Present (State_Dir,"root.state",State_After,Used,Missing_State,Invalid_State);
      if Status /= OK then Close_All; return; end if;
      if Used /= State_After'Length or else State_Bytes /= State_After then
         Fail (Concurrent_Change,Indeterminate); return;
      end if;
      -- A partial suffix is not a complete decision. Never infer absent effects.
      if R.Tail_Bytes /= 0 then Fail (Partial_Tail,Indeterminate); return; end if;
      if RS.Generation = P.Target_Generation then
         if RS.Accepted_Plan /= Expected_Plan or else RS.Package_Set /= P.Package_Set
           or else V.Phase not in Pkg_File_Replay.Commit_Pending | Pkg_File_Replay.Forward_Final
           or else (V.Phase = Pkg_File_Replay.Commit_Pending and then RS.Active_Transaction = Zero_Identity)
         then Fail (State_Log_Disagreement,Conflict); return; end if;
      elsif RS.Generation = P.Base_Generation then
         if V.Phase = Pkg_File_Replay.Forward_Final
           or else (RS.Active_Transaction = Zero_Identity and then V.Phase /= Pkg_File_Replay.Reverse_Final)
         then Fail (State_Log_Disagreement,Conflict); return; end if;
      else Fail (State_Log_Disagreement,Conflict); return;
      end if;
      R.Result := Metadata_Consistent; Status := OK; Close_All;
   exception when others => Fail (Read_Failure,Indeterminate);
   end Inspect;
end Pkg_Recovery_Audit;
