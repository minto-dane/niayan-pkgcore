-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Stop_Barrier with SPARK_Mode is
   use type Word; use type Wide; use type Byte;
   PM : constant Bytes := (77,67,66,65,82,80,48,49);
   SM : constant Bytes := (77,67,66,65,82,83,48,49);
   EM : constant Bytes := (77,67,66,65,82,69,48,49);
   function Valid (P : Policy) return Boolean is
   begin
      if P.Cluster_ID = Zero_Identity or else P.Barrier_ID = Zero_Identity
        or else P.Receiver_Boot = Zero_Identity or else P.Contract = Zero_Digest
        or else P.Change_Plan = Zero_Digest or else P.Inventory = Zero_Digest
        or else P.Guard_Value = Zero_Digest or else P.Epoch = 0
        or else P.Guard_Revision = 0 or else P.Maximum_Age = 0 or else P.Count = 0
      then return False; end if;
      for I in 1..P.Count loop
         if P.Members (I).Node_ID = Zero_Identity or else P.Members (I).Resource_ID = Zero_Identity
           or else P.Members (I).Boot_ID = Zero_Identity or else P.Members (I).Stop_Key = Zero_Digest
           or else P.Members (I).Fence_Key = Zero_Digest
           or else P.Members (I).Stop_Key = P.Members (I).Fence_Key
           or else P.Members (I).Required_Isolation_Paths = 0 then return False; end if;
         for J in 1..I-1 loop
            if P.Members (I).Node_ID = P.Members (J).Node_ID then
               if P.Members (I).Resource_ID = P.Members (J).Resource_ID
                 or else P.Members (I).Boot_ID /= P.Members (J).Boot_ID
                 or else P.Members (I).Stop_Key /= P.Members (J).Stop_Key
               then return False; end if;
            end if;
         end loop;
         -- No node agent may also attest fencing for any other participant.
         for J in 1..P.Count loop
            if P.Members (I).Stop_Key = P.Members (J).Fence_Key then return False; end if;
         end loop;
      end loop;
      return True;
   end Valid;
   function Valid (S : State) return Boolean is
   begin
      if S.Policy_Hash = Zero_Digest or else S.Cluster_ID = Zero_Identity
        or else S.Barrier_ID = Zero_Identity or else S.Receiver_Boot = Zero_Identity
        or else S.Count = 0 then return False; end if;
      for I in 1..S.Count loop
         if S.Members (I).Current = Awaiting and then S.Members (I) /= (Receipt'(others => <>)) then
            return False;
         end if;
         if S.Members (I).Current = Acknowledged and then S.Members (I).Node_Sequence = 0 then return False; end if;
         if S.Members (I).Current = Isolated and then S.Members (I).Fence_Sequence = 0 then return False; end if;
         if S.Members (I).Current = Uncertain and then S.Current /= Blocked then return False; end if;
         if S.Members (I).Current /= Awaiting then
            if S.Members (I).Proof = Zero_Digest or else S.Members (I).Audit_Head = Zero_Digest
              or else S.Members (I).Expires <= S.Members (I).Observed
              or else S.Members (I).Observed > S.Last_Now
              or else (S.Members (I).Node_Sequence = 0 and then S.Members (I).Fence_Sequence = 0)
            then return False; end if;
         end if;
         if S.Current = Sealed and then S.Members (I).Current not in Acknowledged | Isolated
         then return False; end if;
      end loop;
      return True;
   end Valid;
   function Fingerprint (P : Policy) return Digest is (MC_SHA256.Hash (Encode (P)));
   function Ready (P : Policy; S : State; Now : Counter) return Boolean is
   begin
      if not Valid (P) or else not Valid (S) or else S.Current = Blocked
        or else S.Policy_Hash /= Fingerprint (P) or else S.Cluster_ID /= P.Cluster_ID
        or else S.Barrier_ID /= P.Barrier_ID or else S.Receiver_Boot /= P.Receiver_Boot
        or else S.Count /= P.Count or else Now < S.Last_Now then return False; end if;
      for I in 1..S.Count loop
         if S.Members (I).Current not in Acknowledged | Isolated
           or else S.Members (I).Observed > Now or else S.Members (I).Expires <= Now
           or else S.Members (I).Expires - S.Members (I).Observed > P.Maximum_Age
           or else Now - S.Members (I).Observed > P.Maximum_Age then return False; end if;
         if S.Members (I).Current = Isolated and then
           (S.Members (I).Isolation_Paths and P.Members (I).Required_Isolation_Paths)
              /= P.Members (I).Required_Isolation_Paths then return False; end if;
      end loop;
      return True;
   end Ready;
   function Usable (P : Policy; S : State; Now : Counter) return Boolean is
      (S.Current = Sealed and then Ready (P,S,Now));
   procedure Initialize (P : Policy; S : out State; Status : out Outcome) is
   begin
      S := (others => <>); Status := Invalid_Input;
      if not Valid (P) then return; end if;
      S.Policy_Hash := Fingerprint (P); S.Cluster_ID := P.Cluster_ID;
      S.Barrier_ID := P.Barrier_ID; S.Receiver_Boot := P.Receiver_Boot;
      S.Count := P.Count; Status := OK;
   end Initialize;
   procedure Observe (P : Policy; S : in out State; E : Evidence;
      Signature_Verified : Boolean; Now : Counter; Status : out Outcome)
   is
      T : State := S; K : Natural range 0..Capacity := 0;
   begin
      Status := Denied;
      if not Valid (P) or else not Valid (S) or else not Signature_Verified
        or else S.Current = Blocked or else S.Revision = Counter'Last
        or else S.Policy_Hash /= Fingerprint (P) or else E.Policy_Hash /= S.Policy_Hash
        or else S.Cluster_ID /= P.Cluster_ID or else S.Barrier_ID /= P.Barrier_ID
        or else S.Receiver_Boot /= P.Receiver_Boot or else S.Count /= P.Count
        or else E.Epoch /= P.Epoch or else E.Applied_Guard_Revision /= P.Guard_Revision
        or else E.Durable_Receipt = Zero_Digest or else E.Audit_Head = Zero_Digest
        or else Now < S.Last_Now
        or else not MC_Time_Guard.Fresh (E.Stamp,P.Receiver_Boot,Now,P.Maximum_Age)
      then return; end if;
      for I in 1..P.Count loop
         if E.Node_ID = P.Members (I).Node_ID and then E.Resource_ID = P.Members (I).Resource_ID then K := I; end if;
      end loop;
      if K = 0 or else E.Node_ID /= P.Members (K).Node_ID
        or else E.Subject_Boot /= P.Members (K).Boot_ID
        or else E.Stamp.Observed_At < S.Members (K).Observed then return; end if;
      if E.Source = Node_Agent then
         if E.Stamp.Sequence <= S.Members (K).Node_Sequence then Status := Stale; return; end if;
         T.Members (K).Node_Sequence := E.Stamp.Sequence;
      else
         if E.Stamp.Sequence <= S.Members (K).Fence_Sequence then Status := Stale; return; end if;
         T.Members (K).Fence_Sequence := E.Stamp.Sequence;
      end if;
      case E.Kind is
         when Drained =>
            if E.Source /= Node_Agent then return; end if;
            if not E.Durable_Stop_Latch or else not E.Queue_Closed
              or else E.In_Flight /= 0 or else E.Unknown_Effects /= 0
              or else E.Last_Dispatched /= E.Last_Completed
            then
               -- A fresh authenticated regression must invalidate an earlier
               -- seal, not merely be ignored while that seal remains usable.
               T.Members (K).Current := Uncertain; T.Current := Blocked;
            else
            -- Isolation must not silently be downgraded to a node's own assertion.
            if S.Members (K).Current = Isolated then return; end if;
            if E.Last_Completed < S.Members (K).Completed then Status := Stale; return; end if;
               T.Members (K).Current := Acknowledged;
            end if;
         when Fenced =>
            if E.Source /= Fence_Observer then return; end if;
            if not E.Retirement_Durable
              or else (E.Isolation_Paths and P.Members (K).Required_Isolation_Paths)
                /= P.Members (K).Required_Isolation_Paths
            then T.Members (K).Current := Uncertain; T.Current := Blocked;
            else T.Members (K).Current := Isolated; end if;
         when Unsafe =>
            T.Members (K).Current := Uncertain; T.Current := Blocked;
      end case;
      T.Members (K).Observed := E.Stamp.Observed_At; T.Members (K).Expires := E.Stamp.Expires_At;
      T.Members (K).Proof := MC_SHA256.Hash (Encode (E)); T.Members (K).Audit_Head := E.Audit_Head;
      T.Members (K).Isolation_Paths := E.Isolation_Paths;
      if E.Kind = Drained then T.Members (K).Completed := E.Last_Completed; end if;
      T.Revision := S.Revision + 1; T.Last_Now := Now; S := T; Status := OK;
   end Observe;
   procedure Seal (P : Policy; S : in out State; Now : Counter; Status : out Outcome) is
   begin
      Status := Denied;
      if S.Current /= Collecting or else S.Revision = Counter'Last or else not Ready (P,S,Now) then return; end if;
      S.Current := Sealed; S.Last_Now := Now; S.Revision := S.Revision + 1; Status := OK;
   end Seal;
   function Encode (P : Policy) return Policy_Frame is
      B : Policy_Frame := (others => 0); O : Positive;
   begin
      B (1..8) := PM; B (9..24) := P.Cluster_ID; B (25..40) := P.Barrier_ID;
      B (41..56) := P.Receiver_Boot; B (57..88) := P.Contract; B (89..120) := P.Change_Plan;
      B (121..152) := P.Inventory; B (153..184) := P.Guard_Value;
      MC_Codec.Put64 (B,185,Wide (P.Epoch)); MC_Codec.Put64 (B,193,Wide (P.Guard_Revision));
      MC_Codec.Put64 (B,201,Wide (P.Maximum_Age)); B (209) := Byte (P.Count);
      for I in 1..P.Count loop
         O := 257 + (I-1)*128;
         B (O..O+15) := P.Members (I).Node_ID; B (O+16..O+31) := P.Members (I).Resource_ID;
         B (O+32..O+47) := P.Members (I).Boot_ID; B (O+48..O+79) := P.Members (I).Stop_Key;
         B (O+80..O+111) := P.Members (I).Fence_Key;
         MC_Codec.Put32 (B,O+112,P.Members (I).Required_Isolation_Paths);
      end loop;
      B (4_577..4_608) := MC_SHA256.Hash (B (1..4_576)); return B;
   end Encode;
   function Encode (S : State) return State_Frame is
      B : State_Frame := (others => 0); O : Positive;
   begin
      B (1..8) := SM; B (9..40) := S.Policy_Hash; B (41..56) := S.Cluster_ID;
      B (57..72) := S.Barrier_ID; B (73..88) := S.Receiver_Boot;
      MC_Codec.Put64 (B,89,Wide (S.Revision)); MC_Codec.Put64 (B,97,Wide (S.Last_Now));
      B (105) := Byte (Phase'Pos (S.Current)); B (106) := Byte (S.Count);
      for I in 1..S.Count loop
         O := 257 + (I-1)*128; B (O) := Byte (Participant_Phase'Pos (S.Members (I).Current));
         MC_Codec.Put64 (B,O+8,Wide (S.Members (I).Node_Sequence));
         MC_Codec.Put64 (B,O+16,Wide (S.Members (I).Fence_Sequence));
         MC_Codec.Put64 (B,O+24,Wide (S.Members (I).Observed));
         MC_Codec.Put64 (B,O+32,Wide (S.Members (I).Expires));
         B (O+40..O+71) := S.Members (I).Proof; B (O+72..O+103) := S.Members (I).Audit_Head;
         MC_Codec.Put64 (B,O+104,Wide (S.Members (I).Completed));
         MC_Codec.Put32 (B,O+112,S.Members (I).Isolation_Paths);
      end loop;
      B (4_577..4_608) := MC_SHA256.Hash (B (1..4_576)); return B;
   end Encode;
   function Encode (E : Evidence) return Evidence_Frame is
      B : Evidence_Frame := (others => 0);
   begin
      B (1..8) := EM; B (9..40) := E.Policy_Hash; B (41..72) := E.Durable_Receipt;
      B (73..104) := E.Audit_Head; B (105..120) := E.Node_ID;
      B (121..136) := E.Resource_ID; B (137..152) := E.Subject_Boot; B (153..168) := E.Stamp.Boot_ID;
      MC_Codec.Put64 (B,169,Wide (E.Stamp.Sequence)); MC_Codec.Put64 (B,177,Wide (E.Stamp.Observed_At));
      MC_Codec.Put64 (B,185,Wide (E.Stamp.Expires_At)); MC_Codec.Put64 (B,193,Wide (E.Epoch));
      MC_Codec.Put64 (B,201,Wide (E.Applied_Guard_Revision));
      MC_Codec.Put64 (B,209,Wide (E.Last_Dispatched)); MC_Codec.Put64 (B,217,Wide (E.Last_Completed));
      MC_Codec.Put64 (B,225,Wide (E.In_Flight)); MC_Codec.Put64 (B,233,Wide (E.Unknown_Effects));
      MC_Codec.Put32 (B,241,E.Isolation_Paths); B (245) := Byte (Ack_Kind'Pos (E.Kind));
      B (246) := Byte (Channel'Pos (E.Source));
      B (247) := Boolean'Pos (E.Durable_Stop_Latch); B (248) := Boolean'Pos (E.Queue_Closed);
      B (249) := Boolean'Pos (E.Retirement_Durable);
      B (289..320) := MC_SHA256.Hash (B (1..288)); return B;
   end Encode;
   procedure Decode (B : Bytes; P : out Policy; Status : out Outcome) is
      T : Policy; O : Positive;
   begin
      P := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= Policy_Frame'Length then return; end if;
      if B (1..8) /= PM or else B (209) > Capacity then return; end if;
      for I in 0..2 loop if MC_Codec.U64 (B,185+I*8) > Wide (Counter'Last) then return; end if; end loop;
      T.Cluster_ID := B (9..24); T.Barrier_ID := B (25..40); T.Receiver_Boot := B (41..56);
      T.Contract := B (57..88); T.Change_Plan := B (89..120); T.Inventory := B (121..152);
      T.Guard_Value := B (153..184); T.Epoch := Counter (MC_Codec.U64 (B,185));
      T.Guard_Revision := Counter (MC_Codec.U64 (B,193)); T.Maximum_Age := Counter (MC_Codec.U64 (B,201));
      T.Count := Natural (B (209));
      for I in 1..T.Count loop
         O := 257+(I-1)*128; T.Members (I).Node_ID := B (O..O+15);
         T.Members (I).Resource_ID := B (O+16..O+31); T.Members (I).Boot_ID := B (O+32..O+47);
         T.Members (I).Stop_Key := B (O+48..O+79); T.Members (I).Fence_Key := B (O+80..O+111);
         T.Members (I).Required_Isolation_Paths := MC_Codec.U32 (B,O+112);
      end loop;
      if not Valid (T) or else Encode (T) /= B then return; end if; P := T; Status := OK;
   end Decode;
   procedure Decode (B : Bytes; S : out State; Status : out Outcome) is
      T : State; O : Positive;
   begin
      S := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= State_Frame'Length then return; end if;
      if B (1..8) /= SM or else B (105) > 2 or else B (106) > Capacity
        or else MC_Codec.U64 (B,89) > Wide (Counter'Last)
        or else MC_Codec.U64 (B,97) > Wide (Counter'Last) then return; end if;
      T.Policy_Hash := B (9..40); T.Cluster_ID := B (41..56); T.Barrier_ID := B (57..72);
      T.Receiver_Boot := B (73..88); T.Revision := Counter (MC_Codec.U64 (B,89));
      T.Last_Now := Counter (MC_Codec.U64 (B,97)); T.Current := Phase'Val (B (105));
      T.Count := Natural (B (106));
      for I in 1..T.Count loop
         O := 257+(I-1)*128; if B (O) > 3 then return; end if;
         for J in 1..4 loop if MC_Codec.U64 (B,O+J*8) > Wide (Counter'Last) then return; end if; end loop;
         if MC_Codec.U64 (B,O+104) > Wide (Counter'Last) then return; end if;
         T.Members (I).Current := Participant_Phase'Val (B (O));
         T.Members (I).Node_Sequence := Counter (MC_Codec.U64 (B,O+8));
         T.Members (I).Fence_Sequence := Counter (MC_Codec.U64 (B,O+16));
         T.Members (I).Observed := Counter (MC_Codec.U64 (B,O+24));
         T.Members (I).Expires := Counter (MC_Codec.U64 (B,O+32));
         T.Members (I).Proof := B (O+40..O+71); T.Members (I).Audit_Head := B (O+72..O+103);
         T.Members (I).Completed := Counter (MC_Codec.U64 (B,O+104));
         T.Members (I).Isolation_Paths := MC_Codec.U32 (B,O+112);
      end loop;
      if not Valid (T) or else Encode (T) /= B then return; end if; S := T; Status := OK;
   end Decode;
   procedure Decode (B : Bytes; E : out Evidence; Status : out Outcome) is
      T : Evidence;
   begin
      E := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= Evidence_Frame'Length then return; end if;
      if B (1..8) /= EM or else B (245) > 2 or else B (246) > 1
        or else B (247) > 1 or else B (248) > 1 or else B (249) > 1 then return; end if;
      for I in 0..8 loop if MC_Codec.U64 (B,169+I*8) > Wide (Counter'Last) then return; end if; end loop;
      T.Policy_Hash := B (9..40); T.Durable_Receipt := B (41..72); T.Audit_Head := B (73..104);
      T.Node_ID := B (105..120); T.Resource_ID := B (121..136); T.Subject_Boot := B (137..152);
      T.Stamp.Boot_ID := B (153..168); T.Stamp.Sequence := Counter (MC_Codec.U64 (B,169));
      T.Stamp.Observed_At := Counter (MC_Codec.U64 (B,177)); T.Stamp.Expires_At := Counter (MC_Codec.U64 (B,185));
      T.Epoch := Counter (MC_Codec.U64 (B,193)); T.Applied_Guard_Revision := Counter (MC_Codec.U64 (B,201));
      T.Last_Dispatched := Counter (MC_Codec.U64 (B,209)); T.Last_Completed := Counter (MC_Codec.U64 (B,217));
      T.In_Flight := Counter (MC_Codec.U64 (B,225)); T.Unknown_Effects := Counter (MC_Codec.U64 (B,233));
      T.Isolation_Paths := MC_Codec.U32 (B,241); T.Kind := Ack_Kind'Val (B (245));
      T.Source := Channel'Val (B (246)); T.Durable_Stop_Latch := B (247) = 1;
      T.Queue_Closed := B (248) = 1; T.Retirement_Durable := B (249) = 1;
      if Encode (T) /= B then return; end if; E := T; Status := OK;
   end Decode;
end MC_Stop_Barrier;
