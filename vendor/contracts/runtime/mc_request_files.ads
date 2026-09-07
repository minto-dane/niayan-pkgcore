-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Protocol; with MC_Requests; with MC_Signatures; with MC_Gate;
package MC_Request_Files with SPARK_Mode => Off is
   Envelope_Size : constant:=MC_Protocol.Header_Size+MC_Requests.Body_Size+64;
   subtype Envelope is Bytes(1..Envelope_Size);
   procedure Load(Directory : String; Header : out MC_Protocol.Frame_Header;
      Body_Data : out MC_Requests.Request_Bytes; Signature : out MC_Signatures.Signature;
      Witnesses : out MC_Gate.Witness_Set; Status : out Outcome);
   -- Immutable protected receiver spool. Transport (e.g. restricted SFTP or mTLS
   -- broker) is NOT an authority: all request and witness signatures are checked.
   -- No in-process network listener and no remotely supplied executable paths.
end MC_Request_Files;
