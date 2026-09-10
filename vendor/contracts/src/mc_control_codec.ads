-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Control;
package MC_Control_Codec with SPARK_Mode, Pure is
   subtype State_Frame is Bytes (1 .. 256);
   subtype Proposal_Frame is Bytes (1 .. 320);
   subtype Authority_Frame is Bytes (1 .. 1_024);
   function Encode (S : MC_Control.State) return State_Frame with Global => null;
   function Encode (P : MC_Control.Proposal) return Proposal_Frame with Global => null;
   function Encode (A : MC_Control.Authority) return Authority_Frame with Global => null;
   procedure Decode (B : Bytes; S : out MC_Control.State; Status : out Outcome)
     with Global => null;
   procedure Decode (B : Bytes; P : out MC_Control.Proposal; Status : out Outcome)
     with Global => null;
   procedure Decode (B : Bytes; A : out MC_Control.Authority; Status : out Outcome)
     with Global => null;
   -- Big endian. Domain-specific magic; all reserved bytes zero; trailing SHA256.
   -- Hash is an encoding/integrity check, NOT sender authentication.
end MC_Control_Codec;
