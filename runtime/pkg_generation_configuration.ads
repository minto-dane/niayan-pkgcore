-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Generation_Manifest;
package Pkg_Generation_Configuration with SPARK_Mode => Off is
   procedure Unavailable (Generation : Digest; Root_ID, Transaction_ID : Identity;
      Context : Digest; Phase : String; Root_FD : out Integer; Status : out Outcome);
   -- Default source provider: DENIED and no descriptor, including empty choices.
   -- A real provider independently authenticates the generation, source root,
   -- transaction, context, saved decisions, revocation and the requested phase.
   -- It lends a descriptor while retaining its source writer/quiescence lock
   -- throughout the enclosing stage operation and all ordinary authorization
   -- gates. The callee never owns/closes that descriptor or renews consent.
   -- The source is distinct from the inactive stage root. The returned FD is
   -- used under the actual CAS reservation; trusting a path supplied by a UI
   -- or reading identities from the saved record is not independent admission.
   procedure Check_Current (Store : in out MC_Store.Store;
      M : Pkg_Generation_Manifest.Manifest; Root_FD : Integer;
      Deadline : Counter; Status : out Outcome);
   -- Mandatory full verification, not a replaceable provider callback. Caller
   -- also checks the complete generation retention and pins under this Store.
   -- Fresh observations do not qualify applied-state recovery or mount migration.
end Pkg_Generation_Configuration;
