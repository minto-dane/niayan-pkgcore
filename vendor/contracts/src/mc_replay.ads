-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package MC_Replay with SPARK_Mode, Pure is
   type Window is record
      Epoch : Counter := 0;
      Token : Counter := 0;
      Sequence_Number : Counter := 0;
      Request_ID : Identity := Zero_Identity;
      Request_Digest : Digest := Zero_Digest;
   end record;
   type Decision is (Fresh, Exact_Retry, Reject_Stale, Reject_Conflict, Reject_Invalid);
   function Check
     (State : Window; Epoch, Token, Sequence_Number : Counter;
      Request_ID : Identity; Request_Digest : Digest) return Decision
      with Global => null;
   procedure Record_Request
     (State : in out Window; Epoch, Token, Sequence_Number : Counter;
      Request_ID : Identity; Request_Digest : Digest; Result : out Decision)
     with Global => null,
       Post => (if Result not in Fresh | Exact_Retry then State = State'Old);
   -- State must be durable before effects. Exact_Retry means inspect prior outcome,
   -- NOT repeat an external effect. Outstanding transactions must be reconciled
   -- before a newer leadership epoch is allowed to perform effects.
end MC_Replay;
