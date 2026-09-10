-- SPDX-License-Identifier: BSD-3-Clause
with MC_Codec; with MC_SHA256;
package body Pkg_Journal with SPARK_Mode is
   use type Byte; use type Wide;
   function Encode (Value : Log_Record) return Encoded_Record is
      B : Encoded_Record := (others => 0);
   begin
      B(1..4) := (16#4D#,16#43#,16#4A#,16#31#);
      MC_Codec.Put16(B,5,1);
      MC_Codec.Put64(B,9,Wide(Value.Sequence_Number));
      MC_Codec.Put64(B,17,Wide(Value.Membership_Epoch));
      MC_Codec.Put64(B,25,Wide(Value.Fence_Token));
      B(33..48) := Value.Transaction_ID;
      B(49) := Byte(Pkg_Transactions.Phase'Pos(Value.Current));
      B(57..88) := Value.Plan; B(89..120) := Value.Previous;
      B(121..152) := Value.Before_Image; B(153..184) := Value.After_Image;
      B(185..200) := Value.Root_ID;
      MC_Codec.Put64(B,201,Wide(Value.Recorded_At));
      B(225..256) := MC_SHA256.Hash(B(1..224));
      return B;
   end Encode;
   procedure Decode (Data : Bytes; Value : out Log_Record; Status : out Outcome) is
      B : Encoded_Record;
   begin
      Value := (others => <>); Status := Invalid_Input;
      if Data'Length /= Record_Size then return; end if;
      B := Data;
      if B(1..4) /= Bytes'(16#4D#,16#43#,16#4A#,16#31#)
        or else MC_Codec.U16(B,5) /= 1
        or else not Is_Zero(B(7..8)) or else not Is_Zero(B(50..56))
        or else not Is_Zero(B(209..224))
        or else B(49) > Pkg_Transactions.Phase'Pos(Pkg_Transactions.Phase'Last)
      then return; end if;
      if MC_SHA256.Hash(B(1..224)) /= B(225..256) then Status := Corrupt; return; end if;
      for J in 0 .. 2 loop
         if MC_Codec.U64(B,9+J*8) > Wide(Counter'Last) then return; end if;
      end loop;
      if MC_Codec.U64(B,201) > Wide(Counter'Last) then return; end if;
      Value.Sequence_Number := Counter(MC_Codec.U64(B,9));
      Value.Membership_Epoch := Counter(MC_Codec.U64(B,17));
      Value.Fence_Token := Counter(MC_Codec.U64(B,25));
      Value.Transaction_ID := B(33..48);
      Value.Current := Pkg_Transactions.Phase'Val(Integer(B(49)));
      Value.Plan := B(57..88); Value.Previous := B(89..120);
      Value.Before_Image := B(121..152); Value.After_Image := B(153..184);
      Value.Root_ID := B(185..200);
      Value.Recorded_At := Counter(MC_Codec.U64(B,201));
      if Value.Sequence_Number = 0 or else Value.Membership_Epoch = 0 or else Value.Fence_Token = 0
        or else Is_Zero(Value.Transaction_ID) or else Is_Zero(Value.Plan)
        or else Is_Zero(Value.Root_ID)
      then return; end if;
      Status := OK;
   end Decode;
   procedure Extend (State : in out Head; Value : Log_Record; Status : out Outcome) is
      B : Encoded_Record;
   begin
      Status := Corrupt;
      if State.Sequence_Number = Counter'Last then Status := Exhausted; return; end if;
      if Is_Zero(State.Root_ID) or else Value.Root_ID /= State.Root_ID
        or else Value.Sequence_Number /= State.Sequence_Number+1
        or else Value.Previous /= State.Last_Digest
        or else Value.Membership_Epoch < State.Membership_Epoch
        or else Value.Fence_Token < State.Fence_Token
        or else Value.Membership_Epoch = 0 or else Value.Fence_Token = 0
        or else Is_Zero(Value.Transaction_ID) or else Is_Zero(Value.Plan)
      then return; end if;
      B := Encode(Value);
      State.Sequence_Number := Value.Sequence_Number;
      State.Membership_Epoch := Value.Membership_Epoch;
      State.Fence_Token := Value.Fence_Token;
      State.Last_Digest := B(225..256);
      Status := OK;
   end Extend;
end Pkg_Journal;
