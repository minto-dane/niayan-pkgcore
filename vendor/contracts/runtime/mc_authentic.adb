-- SPDX-License-Identifier: MIT
with Interfaces.C; with System; with MC_Codec;
package body MC_Authentic with SPARK_Mode => Off is
   use Interfaces.C;
   function Verify_Ed25519(Sig,Message : System.Address; Length : unsigned_long_long;
                           Key : System.Address) return int
     with Import,Convention=>C,External_Name=>"crypto_sign_ed25519_verify_detached";
   function Init return int with Import,Convention=>C,External_Name=>"sodium_init";
   procedure Verify(Domain : String; Data : Bytes; Signature : MC_Signatures.Signature;
                    Key : MC_Signatures.Public_Key; Status : out Outcome) is
   begin
      Status:=Invalid_Input;
      if Domain'Length=0 or else Domain'Length>64 or else Data'Length>16_777_216 then return; end if;
      if Init<0 then Status:=IO_Error; return; end if;
      declare M : Bytes(1..2+Domain'Length+Data'Length); P : Natural:=2; begin
         MC_Codec.Put16(M,1,Domain'Length);
         for C of Domain loop P:=P+1; M(P):=Byte(Character'Pos(C)); end loop;
         M(P+1..M'Last):=Data;
         Status:=(if Verify_Ed25519(Signature'Address,M'Address,M'Length,Key'Address)=0 then OK else Denied);
      end;
   end Verify;
end MC_Authentic;
