-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Qualification with SPARK_Mode is
   use type MC_Release.Evidence_State; use type MC_Release.Evidence_Item;
   use type Byte; use type Wide;
   function Valid (P : Policy) return Boolean is
   begin
      if P.Source_Set = Zero_Digest or else P.Binary_Set = Zero_Digest
        or else P.Contract = Zero_Digest or else P.Platform = Zero_Digest
        or else P.Policy_ID = Zero_Digest or else P.Trust_Epoch = 0
        or else P.Max_Lifetime = 0 or else P.Count < 3 then return False; end if;
      for I in 1 .. P.Count loop
         if P.Keys (I).Key = Zero_Digest or else P.Keys (I).Principal = Zero_Identity
           or else P.Keys (I).Domain = 0 then return False; end if;
         for J in 1 .. I-1 loop
            if P.Keys (I).Key = P.Keys (J).Key then return False; end if;
         end loop;
      end loop;
      return True;
   end Valid;
   function Encode (C : Claim) return Frame is
      B : Frame := (others => 0);
   begin
      B (1..8) := (77,67,81,85,65,76,48,49); -- MCQUAL01
      B (9) := Byte (MC_Release.Evidence_Item'Pos (C.Item));
      B (10) := Byte (MC_Release.Evidence_State'Pos (C.Result));
      B (17..48) := C.Issuer; B (49..80) := C.Source_Set; B (81..112) := C.Binary_Set;
      B (113..144) := C.Contract; B (145..176) := C.Platform; B (177..208) := C.Report;
      B (209..240) := C.Policy_ID; MC_Codec.Put64 (B,241,Wide (C.Not_Before));
      MC_Codec.Put64 (B,249,Wide (C.Expires)); MC_Codec.Put64 (B,257,Wide (C.Trust_Epoch));
      B (289..320) := MC_SHA256.Hash (B (1..288)); return B;
   end Encode;
   procedure Decode (B : Bytes; C : out Claim; Status : out Outcome) is
      F : Frame; T : Claim;
   begin
      C := (others => <>); Status := Invalid_Input; if B'Length /= 320 then return; end if; F := B;
      if F (1..8) /= Bytes'(77,67,81,85,65,76,48,49)
        or else F (9) > MC_Release.Evidence_Item'Pos (MC_Release.Evidence_Item'Last)
        or else F (10) > MC_Release.Evidence_State'Pos (MC_Release.Evidence_State'Last)
      then return; end if;
      for P in 0 .. 2 loop if MC_Codec.U64 (F,241+P*8) > Wide (Counter'Last) then return; end if; end loop;
      T.Item := MC_Release.Evidence_Item'Val (F (9)); T.Result := MC_Release.Evidence_State'Val (F (10));
      T.Issuer := F (17..48); T.Source_Set := F (49..80); T.Binary_Set := F (81..112);
      T.Contract := F (113..144); T.Platform := F (145..176); T.Report := F (177..208);
      T.Policy_ID := F (209..240); T.Not_Before := Counter (MC_Codec.U64 (F,241));
      T.Expires := Counter (MC_Codec.U64 (F,249)); T.Trust_Epoch := Counter (MC_Codec.U64 (F,257));
      if Encode (T) /= F then Status := Corrupt; return; end if;
      C := T; Status := OK;
   end Decode;
   function Evaluate (P : Policy; C : Claims; Verified : Signature_Results;
      Now : Counter) return Assessment is
      A : Assessment; Build, Review, Approve : Natural range 0 .. Authority_List'Last := 0;
      Who : Natural range 0 .. Authority_List'Last;
   begin
      if not Valid (P) then return A; end if;
      A.Eligible := True;
      for I in MC_Release.Evidence_Item loop
         Who := 0;
         for K in 1 .. P.Count loop if C (I).Issuer = P.Keys (K).Key then Who := K; end if; end loop;
         A.Invalid (I) := not Verified (I) or else C (I).Item /= I or else Who = 0
           or else C (I).Result /= MC_Release.Passed or else C (I).Report = Zero_Digest
           or else C (I).Source_Set /= P.Source_Set or else C (I).Binary_Set /= P.Binary_Set
           or else C (I).Contract /= P.Contract or else C (I).Platform /= P.Platform
           or else C (I).Policy_ID /= P.Policy_ID or else C (I).Trust_Epoch /= P.Trust_Epoch
           or else C (I).Not_Before > Now or else C (I).Expires <= Now
           or else C (I).Expires <= C (I).Not_Before
           or else C (I).Expires-C (I).Not_Before > P.Max_Lifetime;
         if not A.Invalid (I) then
            case I is
               when MC_Release.Compiler_Build =>
                  Build := Who; A.Invalid (I) := P.Keys (Who).Duty /= Builder;
               when MC_Release.Independent_Review =>
                  Review := Who; A.Invalid (I) := P.Keys (Who).Duty /= Security_Reviewer;
               when MC_Release.Operational_Approval =>
                  Approve := Who; A.Invalid (I) := P.Keys (Who).Duty /= Operations_Approver;
               when others => null;
            end case;
         end if;
         if A.Invalid (I) then A.Eligible := False; end if;
      end loop;
      if Build > 0 and then Review > 0 and then Approve > 0 then
         A.Independent_Roles := P.Keys (Build).Principal /= P.Keys (Review).Principal
           and then P.Keys (Build).Principal /= P.Keys (Approve).Principal
           and then P.Keys (Review).Principal /= P.Keys (Approve).Principal
           and then P.Keys (Build).Domain /= P.Keys (Review).Domain
           and then P.Keys (Build).Domain /= P.Keys (Approve).Domain
           and then P.Keys (Review).Domain /= P.Keys (Approve).Domain;
      end if;
      A.Eligible := A.Eligible and A.Independent_Roles; return A;
   end Evaluate;
end MC_Qualification;
