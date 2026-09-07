-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Pkg_File_Replay;
package Pkg_Recovery_Audit with SPARK_Mode => Off is
   type Finding is (Unchecked, Metadata_Consistent, Missing_State, Invalid_State,
      Missing_Plan, Invalid_Plan, Missing_Pin, Invalid_Pin, Missing_Journal,
      Empty_Journal, Bad_Record, Partial_Tail, State_Log_Disagreement,
      Concurrent_Change, Read_Failure, Limit_Exceeded);
   type Report is record
      Result : Finding := Unchecked;
      Root_ID, Transaction_ID : Identity := Zero_Identity;
      Plan_Digest, Journal_Head, Tail_Digest : Digest := Zero_Digest;
      Root_Generation, Complete_Records, Bad_Record_Number : Counter := 0;
      Tail_Bytes : Natural range 0 .. 255 := 0;
      Log_State : Pkg_File_Replay.View;
      -- This tool cannot acquire a distributed stop barrier or attest the host.
      -- Its only output is a diagnostic observation, never an execution permit.
      Physical_Files_Checked, Recovery_Objects_Checked, Trust_Checked : Boolean := False;
   end record;
   procedure Inspect (State_Path, Store_Path : String; Expected_Plan : Digest;
                      R : out Report; Status : out Outcome);
   -- Read-only: no Create, no MC_Store.Open, no log repair, no lock-file creation.
   -- Use a consistent forensic copy or a quiesced writer for authoritative review.
   -- Size/hash/identity rechecks detect some races, not same-value ABA or hostile root.
end Pkg_Recovery_Audit;
