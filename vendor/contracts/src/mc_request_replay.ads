-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Log_Format; with MC_Replay;
package MC_Request_Replay with SPARK_Mode, Pure is
   Genesis : constant := 199;
   Begun : constant := 200;
   Known_OK : constant := 201;
   Known_Failure : constant := 202;
   Unknown_Outcome : constant := 203;
   type State is record
      Count : Counter := 0;
      Root_ID : Identity := Zero_Identity;
      Window : MC_Replay.Window;
      Pending : Boolean := False;
      Serial : Counter := 0;
      Last_Result : Outcome := Indeterminate;
   end record;
   procedure Consume (S : in out State; E : MC_Log_Format.Log_Entry;
                      Status : out Outcome)
     with Global => null,
       Post => (if Status /= OK then S = S'Old);
   -- Genesis is optional ONLY for an already nonempty legacy ledger. New ledgers
   -- must be explicitly initialized. Empty or absent is never replay-safe.
end MC_Request_Replay;
