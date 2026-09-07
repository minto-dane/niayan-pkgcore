-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_FS; with MC_Control;
package MC_Control_IO with SPARK_Mode => Off is
   subtype Signature_Bundle is Bytes (1 .. 512);
   procedure Read_State (Directory : MC_FS.Root; Scope : Identity;
      S : out MC_Control.State; Fingerprint : out Digest; Status : out Outcome);
   procedure Check (Directory : MC_FS.Root; Scope : Identity;
      Action : MC_Control.Operation; Status : out Outcome);
   procedure Submit (Directory_Path : String; Scope : Identity;
      Raw_Proposal : Bytes; Signatures : Signature_Bundle; Status : out Outcome);
   -- Protected/non-rollback policy directory; no network or implicit bootstrap.
   -- control-authorities.bin is provisioned out-of-band. First signed proposal
   -- can create ONLY a quarantined state. Relaxation needs two independent roles.
   -- Every accepted state and proposal is retained before the current pointer is
   -- replaced. A write failure after publication is indeterminate, never success.
   -- Revocation applies to the next dispatch check, not an already-running effect.
   -- Keys cannot be rotated by silently replacing the authority file: mismatch
   -- with the accepted state fails closed. Offline key migration is not provided.
end MC_Control_IO;
