-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Control with SPARK_Mode is
   function Valid (A : Authority) return Boolean is
      Have_Ops, Have_Security : Boolean := False;
   begin
      if A.Scope = Zero_Identity or else A.Contract = Zero_Digest
        or else A.Serial = 0 or else A.Count < 2
        or else A.Tighten_Threshold > A.Count or else A.Resume_Threshold > A.Count
      then return False; end if;
      for I in 1 .. A.Count loop
         if A.Keys (I).Public_Key = Zero_Digest
           or else A.Keys (I).Principal = Zero_Identity or else A.Keys (I).Domain = 0
         then return False; end if;
         for J in 1 .. I - 1 loop
            if A.Keys (I).Public_Key = A.Keys (J).Public_Key
              or else A.Keys (I).Principal = A.Keys (J).Principal
            then return False; end if;
         end loop;
         Have_Ops := Have_Ops or else A.Keys (I).Duty = Operations;
         Have_Security := Have_Security or else A.Keys (I).Duty = Security;
      end loop;
      return Have_Ops and then Have_Security;
   end Valid;
   function Valid (S : State) return Boolean is
     (S.Scope /= Zero_Identity and then S.Contract /= Zero_Digest
      and then S.Authority_Digest /= Zero_Digest and then S.Revision > 0
      and then S.Trust_Epoch > 0 and then S.Last_Request /= Zero_Identity
      and then S.Reason /= Zero_Digest
      and then ((S.Current = Running) = (S.Incident = Zero_Identity))
      and then ((S.Revision = 1 and then S.Previous = Zero_Digest)
        or else (S.Revision > 1 and then S.Previous /= Zero_Digest)));
   function Permits (Current : Mode; Action : Operation) return Boolean is
     (case Current is
         when Running => True,
         when Changes_Held => Action in Inspect | Contain | Repair_Records,
         when Quarantined => Action in Inspect | Contain);
   procedure Decide
     (A : Authority; Authority_Hash : Digest; Before : State;
      Before_Hash : Digest; Is_Genesis : Boolean; P : Proposal;
      Verified : Verified_Set; Boot : Identity; Now : Counter;
      After : out State; Status : out Outcome)
   is
      Count : Natural := 0;
      Ops, Sec, Diverse : Boolean := False;
      First_Domain : Natural := 0;
      Relaxing : Boolean;
   begin
      After := Before; Status := Denied;
      if not Valid (A) or else Authority_Hash = Zero_Digest
        or else P.Scope /= A.Scope or else P.Contract /= A.Contract
        or else P.Authority_Digest /= Authority_Hash
        or else Boot = Zero_Identity or else P.Boot_ID /= Boot
        or else P.Request_ID = Zero_Identity or else P.Reason = Zero_Digest
        or else P.Not_Before > Now or else P.Expires <= Now
        or else P.Expires <= P.Not_Before
        or else P.Expires - P.Not_Before > 300_000
        or else P.Expected_Revision = Counter'Last or else P.New_Trust_Epoch = 0
      then return; end if;
      if Is_Genesis then
         if P.Expected_Revision /= 0 or else P.Expected_State /= Zero_Digest
           or else Before_Hash /= Zero_Digest or else P.Desired /= Quarantined
         then return; end if;
         Relaxing := False;
      else
         if not Valid (Before) or else Before.Scope /= A.Scope
           or else Before.Contract /= A.Contract
           or else Before.Authority_Digest /= Authority_Hash
           or else Before_Hash = Zero_Digest or else P.Expected_State /= Before_Hash
           or else P.Expected_Revision /= Before.Revision
           or else P.New_Trust_Epoch < Before.Trust_Epoch
           or else P.Request_ID = Before.Last_Request
         then return; end if;
         Relaxing := Mode'Pos (P.Desired) < Mode'Pos (Before.Current);
      end if;
      for I in Signer_Index loop
         if Verified (I) then
            if I > A.Count then return; end if;
            Count := Count + 1;
            Ops := Ops or else A.Keys (I).Duty = Operations;
            Sec := Sec or else A.Keys (I).Duty = Security;
            if First_Domain = 0 then First_Domain := A.Keys (I).Domain;
            elsif First_Domain /= A.Keys (I).Domain then Diverse := True; end if;
         end if;
      end loop;
      if Count < A.Tighten_Threshold then return; end if;
      if Relaxing and then
        (Count < A.Resume_Threshold or else not Ops or else not Sec or else not Diverse
         or else P.New_Trust_Epoch <= Before.Trust_Epoch
         or else P.Recovery_Receipt = Zero_Digest)
      then return; end if;
      After.Scope := A.Scope; After.Contract := A.Contract;
      After.Authority_Digest := Authority_Hash;
      After.Revision := P.Expected_Revision + 1; After.Trust_Epoch := P.New_Trust_Epoch;
      After.Current := P.Desired; After.Last_Request := P.Request_ID;
      After.Incident := (if P.Desired = Running then Zero_Identity else P.Request_ID);
      After.Previous := Before_Hash; After.Reason := P.Reason; Status := OK;
   end Decide;
end MC_Control;
