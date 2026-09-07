-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Breakglass with SPARK_Mode, Pure is
   type Action is
     (Observe, Contain_Service, Isolate_Node, Preserve_Evidence,
      Restore_Accepted_State, Rotate_Credential, Disable_Verification,
      Disable_Audit, Disable_Encryption);
   type Request is record
      Request_ID, Scope, Reason, Evidence : Digest := Zero_Digest;
      Trust_Epoch, Not_Before, Expires_At : Counter := 0;
      Operations_Approved, Security_Approved : Boolean := False;
      Independent_Approvers, Audit_Sink_Reachable : Boolean := False;
      Requested : Action := Observe;
   end record;
   function Permitted (R : Request; Now, Current_Trust_Epoch : Counter) return Boolean
     with Global => null;
   -- There is deliberately no emergency path that can disable verification,
   -- audit, or encryption.  Recovery must preserve the security boundary.
end MC_Breakglass;
