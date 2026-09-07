-- SPDX-License-Identifier: MIT
with MC_Codec; with MC_SHA256;
package body MC_Log_Format with SPARK_Mode is
   use type Wide;
   Magic : constant Bytes := (16#4D#,16#43#,16#4C#,16#4F#,16#47#,16#30#,16#30#,16#32#);
   function Encode(E : Log_Entry) return Frame is
      B : Frame:=(others=>0);
   begin
      B(1..8):=Magic; MC_Codec.Put64(B,9,Wide(E.Sequence)); MC_Codec.Put16(B,17,E.Kind);
      B(19):=Byte(Outcome'Pos(E.Result)); B(25..40):=E.Root_ID; B(41..56):=E.Operation_ID;
      MC_Codec.Put64(B,57,Wide(E.Epoch)); MC_Codec.Put64(B,65,Wide(E.Token));
      MC_Codec.Put64(B,73,Wide(E.Index)); MC_Codec.Put64(B,81,Wide(E.Generation));
      B(89..120):=E.Object; B(121..152):=E.Previous;
      B(225..256):=MC_SHA256.Hash(B(1..224)); return B;
   end Encode;
   procedure Decode(B : Bytes; E : out Log_Entry; Status : out Outcome) is
   type Offsets is array(1..5) of Positive;
      Checks : constant Offsets:=(9,57,65,73,81);
   begin
      E:=(others=><>); Status:=Corrupt;
      if B'Length/=Record_Size or else B'First/=1 or else B(1..8)/=Magic
        or else B(225..256)/=MC_SHA256.Hash(B(1..224)) then return; end if;
      for J in 20..24 loop if B(J)/=0 then return; end if; end loop;
      for J in 153..224 loop if B(J)/=0 then return; end if; end loop;
      if Natural(B(19))>Outcome'Pos(Outcome'Last) then return; end if;
      for Offset of Checks loop
         if MC_Codec.U64(B,Offset)>Wide(Counter'Last) then return; end if;
      end loop;
      E.Sequence:=Counter(MC_Codec.U64(B,9)); E.Kind:=MC_Codec.U16(B,17);
      E.Result:=Outcome'Val(B(19)); E.Root_ID:=B(25..40); E.Operation_ID:=B(41..56);
      E.Epoch:=Counter(MC_Codec.U64(B,57)); E.Token:=Counter(MC_Codec.U64(B,65));
      E.Index:=Counter(MC_Codec.U64(B,73)); E.Generation:=Counter(MC_Codec.U64(B,81));
      E.Object:=B(89..120); E.Previous:=B(121..152);
      if E.Sequence=0 or else E.Kind=0 or else E.Root_ID=Zero_Identity
         or else E.Operation_ID=Zero_Identity then return; end if;
      Status:=OK;
   end Decode;
end MC_Log_Format;
