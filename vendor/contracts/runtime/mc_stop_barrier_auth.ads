-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Stop_Barrier; with MC_Signatures;
package MC_Stop_Barrier_Auth with SPARK_Mode => Off is
   Domain : constant String := "MISSION-CORE-STOP-ACK-v1";
   procedure Verify (P : MC_Stop_Barrier.Policy; Raw : Bytes;
      Signature : MC_Signatures.Signature; E : out MC_Stop_Barrier.Evidence;
      Status : out Outcome);
   -- P is independently authenticated and bound to the approved inventory.
   -- No key is accepted from Raw. Hash/canonicality is not authentication.
end MC_Stop_Barrier_Auth;
