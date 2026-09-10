-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Log_Format with SPARK_Mode, Pure is
   Record_Size : constant := 256;
   subtype Frame is Bytes(1..Record_Size);
   type Log_Entry is record
      Sequence : Counter := 0;
      Kind : Natural range 0..65_535 := 0;
      Root_ID, Operation_ID : Identity := Zero_Identity;
      Epoch, Token, Index, Generation : Counter := 0;
      Object, Previous : Digest := Zero_Digest;
      Result : Outcome := OK;
   end record;
   function Encode(E : Log_Entry) return Frame with Global=>null;
   procedure Decode(B : Bytes; E : out Log_Entry; Status : out Outcome) with Global=>null;
   -- Digest protects framing and accidental corruption, not malicious rollback.
   -- Interpretation of Kind and valid transitions is the caller's responsibility.
end MC_Log_Format;
