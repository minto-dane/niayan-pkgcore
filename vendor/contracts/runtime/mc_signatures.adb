-- SPDX-License-Identifier: MIT
with Interfaces.C; with System; with MC_SHA256;
package body MC_Signatures with SPARK_Mode => Off is
   use type Interfaces.C.int;
   function Sodium_Init return Interfaces.C.int
     with Import, Convention => C, External_Name => "sodium_init";
   function Verify_Detached
     (Sig : System.Address; Data : System.Address;
      Length : Interfaces.C.unsigned_long_long; Key : System.Address)
      return Interfaces.C.int
     with Import, Convention => C, External_Name => "crypto_sign_verify_detached";
   Domain : constant Bytes (1 .. 16) :=
     (16#4D#,16#43#,16#50#,16#32#,16#2D#,16#53#,16#49#,16#47#,
      16#4E#,16#45#,16#44#,16#2D#,16#56#,16#32#,0,0);
   procedure Verify
     (Raw_Header : Bytes; Body_Data : Bytes; Sig : Signature;
      Trusted_Key : Public_Key; Message : out Verified_Message; Status : out Outcome) is
      H : MC_Protocol.Header;
      Signed_Data : aliased Bytes (1 .. 176) := (others => 0);
      Local_Key : aliased Public_Key := Trusted_Key;
      Local_Sig : aliased Signature := Sig;
   begin
      Message := (others => <>);
      MC_Protocol.Decode (Raw_Header, H, Status);
      if Status /= OK then return; end if;
      Status := Denied;
      if Is_Zero (Trusted_Key) or else not MC_Protocol.Valid_Identity (H)
        or else Body_Data'Length /= H.Body_Length
        or else MC_SHA256.Hash (Body_Data) /= H.Body_Digest
      then return; end if;
      if Sodium_Init < 0 then Status := IO_Error; return; end if;
      Signed_Data (1 .. 16) := Domain;
      Signed_Data (17 .. 176) := MC_Protocol.Encode (H);
      if Verify_Detached (Local_Sig'Address, Signed_Data'Address,
                         Signed_Data'Length, Local_Key'Address) /= 0 then
         return;
      end if;
      Message := (Is_Verified => True, Value => H);
      Status := OK;
   end Verify;
   function Authenticated (Message : Verified_Message) return Boolean is
     (Message.Is_Verified);
   function Content (Message : Verified_Message) return MC_Protocol.Header is
     (Message.Value);
end MC_Signatures;
