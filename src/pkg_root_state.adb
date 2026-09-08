-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body Pkg_Root_State with SPARK_Mode is
   use type MC_Types.Byte;
   use type Wide;
   Magic : constant Bytes := (16#4D#,16#43#,16#52#,16#4F#,16#4F#,16#54#,16#30#,16#32#);
   function Encode(S : State) return Frame is
      B : Frame:=(others=>0);
   begin
      B(1..8):=Magic; B(9..24):=S.Root_ID; MC_Codec.Put64(B,25,Wide(S.Generation));
      B(33..48):=S.Active_Transaction; B(49..80):=S.Active_Plan;
      B(81..112):=S.Accepted_Plan; B(113..144):=S.Package_Set;
      B(161..192):=MC_SHA256.Hash(B(1..160)); return B;
   end;
   procedure Decode(B : Bytes; S : out State; Status : out Outcome) is
   begin
      S:=(others=><>); Status:=Corrupt;
      if B'First/=1 or else B'Length/=192 or else B(1..8)/=Magic
        or else B(161..192)/=MC_SHA256.Hash(B(1..160))
        or else MC_Codec.U64(B,25)>Wide(Counter'Last) then return; end if;
      for J in 145..160 loop if B(J)/=0 then return; end if; end loop;
      S.Root_ID:=B(9..24); S.Generation:=Counter(MC_Codec.U64(B,25));
      S.Active_Transaction:=B(33..48); S.Active_Plan:=B(49..80);
      S.Accepted_Plan:=B(81..112); S.Package_Set:=B(113..144);
      if S.Root_ID=Zero_Identity or else ((S.Active_Transaction=Zero_Identity)/=(S.Active_Plan=Zero_Digest)) then return; end if;
      if S.Generation>0 and then (S.Accepted_Plan=Zero_Digest or else S.Package_Set=Zero_Digest) then return; end if;
      Status:=OK;
   end;
end Pkg_Root_State;
