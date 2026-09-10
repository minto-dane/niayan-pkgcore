-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with Pkg_Inventory; with Pkg_Self_Repair;
package Pkg_Scrubber with SPARK_Mode=>Off is
   procedure Scan(Root_Path,State_Path : String; Baseline : Pkg_Inventory.Manifest;
      Maximum_Read_Bytes, Deadline_Boottime_Ms : Counter;
      Findings : out Pkg_Self_Repair.Finding_Array;
      Matched,Different,Unknown : out Natural; Status : out Outcome);
   -- Holds the ordinary package root lock and rechecks generation at completion.
   -- No mutation of managed files, no deleting data to make space, no root '/'.
   -- Deadline is checked between files; a blocked kernel I/O needs OS-level
   -- supervision. This API does not promise cancellation of uninterruptible I/O.
end Pkg_Scrubber;
