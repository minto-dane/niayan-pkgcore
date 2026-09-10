-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Durable; with Pkg_Journal;
package Pkg_Journal_IO with SPARK_Mode => Off is
   procedure Scan
     (File : MC_Durable.File_Handle; Expected_Root : Identity;
      Result : out Pkg_Journal.Head; Status : out Outcome);
   procedure Check_Anchor
     (Actual, Authenticated_Anchor : Pkg_Journal.Head; Status : out Outcome);
   procedure Append
     (File : in out MC_Durable.File_Handle; State : in out Pkg_Journal.Head;
      Item : Pkg_Journal.Log_Record; Status : out Outcome);
   -- Scan validates structure and chaining, not authenticity or complete transaction
   -- semantics. Check_Anchor must use an independently authenticated exact head.
   -- Append returns Indeterminate after an uncertain write; reopen/reconcile, never retry blindly.
end Pkg_Journal_IO;
