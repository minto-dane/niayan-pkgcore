-- SPDX-License-Identifier: BSD-3-Clause
with MC_Codec;
package body MC_Protocol with SPARK_Mode is
   use type Byte; use type Word; use type Wide;
   function Encode (Value : Header) return Frame_Header is
      B : Frame_Header := (others => 0);
   begin
      B (1 .. 4) := (16#4D#,16#43#,16#50#,16#31#);
      MC_Codec.Put16 (B, 5, Value.Version_Major);
      MC_Codec.Put16 (B, 7, Value.Version_Minor);
      B (9) := Byte (Message_Kind'Pos (Value.Kind) + 1);
      MC_Codec.Put16 (B, 11, Header_Size);
      MC_Codec.Put32 (B, 13, Word (Value.Body_Length));
      B (17 .. 32) := Value.Request_ID;
      B (33 .. 48) := Value.Cluster_ID;
      B (49 .. 64) := Value.Node_ID;
      B (65 .. 80) := Value.Resource_ID;
      MC_Codec.Put64 (B, 81, Wide (Value.Membership_Epoch));
      MC_Codec.Put64 (B, 89, Wide (Value.Fence_Token));
      MC_Codec.Put64 (B, 97, Wide (Value.Sequence_Number));
      MC_Codec.Put64 (B, 105, Wide (Value.Deadline));
      B (113 .. 128) := Value.Boot_ID;
      B (129 .. 160) := Value.Body_Digest;
      return B;
   end Encode;
   procedure Decode (Data : Bytes; Value : out Header; Status : out Outcome) is
      B : Frame_Header;
   begin
      Value := (others => <>);
      Status := Invalid_Input;
      if Data'Length /= Header_Size then return; end if;
      B := Data;
      if B (1 .. 4) /= Bytes'(16#4D#,16#43#,16#50#,16#31#)
        or else B (10) /= 0 or else MC_Codec.U16 (B, 11) /= Header_Size
      then return; end if;
      if MC_Codec.U16 (B, 5) /= Major or else MC_Codec.U16 (B, 7) /= Minor then
         Status := Unsupported; return;
      end if;
      if B (9) < 1 or else B (9) > Message_Kind'Pos (Message_Kind'Last) + 1
        or else MC_Codec.U32 (B, 13) > Word (Max_Message)
      then return; end if;
      for J in 0 .. 3 loop
         if MC_Codec.U64 (B, 81 + J * 8) > Wide (Counter'Last) then return; end if;
      end loop;
      Value.Kind := Message_Kind'Val (Integer (B (9)) - 1);
      Value.Body_Length := Natural (MC_Codec.U32 (B, 13));
      Value.Request_ID := B (17 .. 32);
      Value.Cluster_ID := B (33 .. 48);
      Value.Node_ID := B (49 .. 64);
      Value.Resource_ID := B (65 .. 80);
      Value.Membership_Epoch := Counter (MC_Codec.U64 (B, 81));
      Value.Fence_Token := Counter (MC_Codec.U64 (B, 89));
      Value.Sequence_Number := Counter (MC_Codec.U64 (B, 97));
      Value.Deadline := Counter (MC_Codec.U64 (B, 105));
      Value.Boot_ID := B (113 .. 128);
      Value.Body_Digest := B (129 .. 160);
      Status := OK;
   end Decode;
   function Valid_Identity (Value : Header) return Boolean is
     (not Is_Zero (Value.Request_ID) and then not Is_Zero (Value.Cluster_ID)
      and then not Is_Zero (Value.Node_ID) and then not Is_Zero (Value.Resource_ID)
      and then not Is_Zero (Value.Boot_ID) and then Value.Sequence_Number > 0
      and then Value.Membership_Epoch > 0 and then Value.Fence_Token > 0);
end MC_Protocol;
