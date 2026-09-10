-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text; with MC_Store; with Pkg_Site_Supply; with Pkg_Supply_Map;
package Pkg_Supply_Planner with SPARK_Mode => Off is
   type Request is record
      Request_ID, Scope, Original, Control, InRelease, Index, Keyring : Digest := Zero_Digest;
      Index_Path, Deb_Path : MC_Text.Value := MC_Text.Empty;
   end record;
   type Requests is array (Positive range <>) of Request;
   procedure Prepare (Store : in out MC_Store.Store; Site : in out Pkg_Site_Supply.Session;
      Transaction_ID : Identity; Target : Pkg_Supply_Map.Context; Items : Requests;
      Observer_UID : Word; Deadline : Counter;
      Map, Retained_Policy : out Digest; Valid_Until : out Counter; Status : out Outcome);
   -- Requires a planning Site session and an already-open Store. Items are
   -- strictly original-sorted, exactly the target-minus-predecessor set; the
   -- native map verifier proves coverage from both retained catalogs/closures.
   -- Keys/epoch/age/UTC are read from protected current Site inputs, never from
   -- caller-supplied authority rows or observer results. Each request refreshes
   -- the same pinned trust, then uses the real observer under the held CAS lock.
   -- The final map/policy are verified with another current Site observation.
   -- Failure closes Site and clears all three outputs, but may leave unreferenced
   -- objects or an advanced independent TUF checkpoint. No retry or root effect.
   -- The caller must bind the completed physical plan via Bind_Publication and
   -- satisfy all managed admission guards. This prepares supply, not execution.
end Pkg_Supply_Planner;
