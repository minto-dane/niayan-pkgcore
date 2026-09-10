-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Journal_Budget with SPARK_Mode, Pure is
   function Fits (Used, Limit, Pending, Added : Counter) return Boolean is
     (Used <= Limit and then Pending <= Limit - Used
      and then Added <= Limit - Used - Pending)
     with Global => null;
   -- Pending denotes already-admitted obligations, not free space. Check before
   -- recording a new intent. Arithmetic is ordered to avoid overflow/underflow.
   -- This is a LOGICAL record budget; disk blocks, inodes, quorum and fsync are
   -- separate obligations. False never licenses history deletion or truncation.
end MC_Journal_Budget;
