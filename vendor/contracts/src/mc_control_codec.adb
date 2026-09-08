-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Control_Codec with SPARK_Mode is
   use type Wide; use type Byte;
   SM : constant Bytes := (77,67,67,84,76,48,48,49);
   PM : constant Bytes := (77,67,80,82,79,80,48,49);
   AM : constant Bytes := (77,67,82,79,76,69,48,49);
   function Encode (S : MC_Control.State) return State_Frame is
      B : State_Frame := (others => 0);
   begin
      B (1..8) := SM; B (9..24) := S.Scope; B (25..56) := S.Contract;
      MC_Codec.Put64 (B,57,Wide (S.Revision)); MC_Codec.Put64 (B,65,Wide (S.Trust_Epoch));
      B (73) := Byte (MC_Control.Mode'Pos (S.Current)); B (81..96) := S.Incident;
      B (97..112) := S.Last_Request; B (113..144) := S.Previous; B (145..176) := S.Reason;
      B (177..208) := S.Authority_Digest; B (225..256) := MC_SHA256.Hash (B (1..224));
      return B;
   end Encode;
   function Encode (P : MC_Control.Proposal) return Proposal_Frame is
      B : Proposal_Frame := (others => 0);
   begin
      B (1..8) := PM; B (9..24) := P.Scope; B (25..56) := P.Contract;
      MC_Codec.Put64 (B,57,Wide (P.Expected_Revision)); MC_Codec.Put64 (B,65,Wide (P.New_Trust_Epoch));
      B (73) := Byte (MC_Control.Mode'Pos (P.Desired)); B (81..96) := P.Boot_ID;
      B (97..112) := P.Request_ID; B (113..144) := P.Expected_State; B (145..176) := P.Reason;
      B (177..208) := P.Recovery_Receipt; B (209..240) := P.Authority_Digest;
      MC_Codec.Put64 (B,241,Wide (P.Not_Before)); MC_Codec.Put64 (B,249,Wide (P.Expires));
      B (289..320) := MC_SHA256.Hash (B (1..288)); return B;
   end Encode;
   function Encode (A : MC_Control.Authority) return Authority_Frame is
      B : Authority_Frame := (others => 0); O : Positive;
   begin
      B (1..8) := AM; B (9..24) := A.Scope; B (25..56) := A.Contract;
      MC_Codec.Put64 (B,57,Wide (A.Serial)); B (65) := Byte (A.Count);
      B (66) := Byte (A.Tighten_Threshold); B (67) := Byte (A.Resume_Threshold);
      for I in 1..A.Count loop
         O := 97 + (I-1)*96;
         B (O..O+31) := A.Keys (I).Public_Key; B (O+32..O+47) := A.Keys (I).Principal;
         MC_Codec.Put16 (B,O+48,A.Keys (I).Domain);
         B (O+50) := Byte (MC_Control.Role'Pos (A.Keys (I).Duty));
      end loop;
      B (993..1_024) := MC_SHA256.Hash (B (1..992)); return B;
   end Encode;
   procedure Decode (B : Bytes; S : out MC_Control.State; Status : out Outcome) is
      T : MC_Control.State;
   begin
      S := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= 256 then return; end if;
      if B (1..8) /= SM or else B (73) > 2
        or else MC_Codec.U64 (B,57) > Wide (Counter'Last)
        or else MC_Codec.U64 (B,65) > Wide (Counter'Last) then return; end if;
      T.Scope := B (9..24); T.Contract := B (25..56);
      T.Revision := Counter (MC_Codec.U64 (B,57)); T.Trust_Epoch := Counter (MC_Codec.U64 (B,65));
      T.Current := MC_Control.Mode'Val (B (73)); T.Incident := B (81..96);
      T.Last_Request := B (97..112); T.Previous := B (113..144); T.Reason := B (145..176);
      T.Authority_Digest := B (177..208);
      if Encode (T) /= B or else not MC_Control.Valid (T) then return; end if;
      S := T; Status := OK;
   end Decode;
   procedure Decode (B : Bytes; P : out MC_Control.Proposal; Status : out Outcome) is
      T : MC_Control.Proposal;
      type Positions is array (Positive range <>) of Positive;
      At_Pos : constant Positions := (57,65,241,249);
   begin
      P := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= 320 then return; end if;
      if B (1..8) /= PM or else B (73) > 2 then return; end if;
      for J in At_Pos'Range loop
         if MC_Codec.U64(B,At_Pos(J))>Wide(Counter'Last) then return; end if;
         pragma Loop_Invariant
           (for all K in At_Pos'First .. J => MC_Codec.U64(B,At_Pos(K))<=Wide(Counter'Last));
      end loop;
      T.Scope := B (9..24); T.Contract := B (25..56);
      T.Expected_Revision := Counter (MC_Codec.U64 (B,57)); T.New_Trust_Epoch := Counter (MC_Codec.U64 (B,65));
      T.Desired := MC_Control.Mode'Val (B (73)); T.Boot_ID := B (81..96); T.Request_ID := B (97..112);
      T.Expected_State := B (113..144); T.Reason := B (145..176); T.Recovery_Receipt := B (177..208);
      T.Authority_Digest := B (209..240); T.Not_Before := Counter (MC_Codec.U64 (B,241));
      T.Expires := Counter (MC_Codec.U64 (B,249));
      if Encode (T) /= B then return; end if; P := T; Status := OK;
   end Decode;
   procedure Decode (B : Bytes; A : out MC_Control.Authority; Status : out Outcome) is
      T : MC_Control.Authority; O : Positive;
   begin
      A := (others => <>); Status := Corrupt;
      if B'First /= 1 or else B'Length /= 1_024 then return; end if;
      if B (1..8) /= AM or else B (65) > 8 or else B (66) not in 1..8
        or else B (67) not in 2..8 or else MC_Codec.U64 (B,57) > Wide (Counter'Last)
      then return; end if;
      T.Scope := B (9..24); T.Contract := B (25..56); T.Serial := Counter (MC_Codec.U64 (B,57));
      T.Count := Natural (B (65)); T.Tighten_Threshold := Natural (B (66)); T.Resume_Threshold := Natural (B (67));
      for I in 1..T.Count loop
         pragma Loop_Invariant(T.Count=Natural(B(65)));
         O := 97 + (I-1)*96; if B (O+50) > 1 then return; end if;
         T.Keys (I).Public_Key := B (O..O+31); T.Keys (I).Principal := B (O+32..O+47);
         T.Keys (I).Domain := MC_Codec.U16 (B,O+48); T.Keys (I).Duty := MC_Control.Role'Val (B (O+50));
      end loop;
      if Encode (T) /= B or else not MC_Control.Valid (T) then return; end if;
      A := T; Status := OK;
   end Decode;
end MC_Control_Codec;
