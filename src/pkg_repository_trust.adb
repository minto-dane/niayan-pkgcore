-- SPDX-License-Identifier: MIT
package body Pkg_Repository_Trust with SPARK_Mode is
   function Check (M : Metadata; A : Anchor; Now : Counter) return Decision is
   begin
      if M.Repository_ID=Zero_Digest or else M.Snapshot=Zero_Digest or else M.Root_Keys=Zero_Digest
        or else M.Repository_Epoch=0 or else M.Snapshot_Version=0 or else M.Timestamp_Version=0
        or else M.Produced_At=0 or else M.Expires_At<=M.Produced_At then return Invalid; end if;
      if M.Repository_ID/=A.Repository_ID or else M.Root_Keys/=A.Root_Keys then return Wrong_Repository; end if;
      if not M.Root_Signed or else not M.Snapshot_Signed or else not M.Timestamp_Signed then return Unauthenticated; end if;
      if M.Produced_At>Now or else M.Expires_At<=Now then return Expired; end if;
      if M.Repository_Epoch<A.Minimum_Epoch or else M.Snapshot_Version<A.Minimum_Snapshot_Version
        or else M.Timestamp_Version<A.Minimum_Timestamp_Version then return Rollback; end if;
      if A.Last_Snapshot/=Zero_Digest and then M.Snapshot_Version=A.Minimum_Snapshot_Version
        and then M.Snapshot/=A.Last_Snapshot then return Rollback; end if;
      return Trusted;
   end Check;
end Pkg_Repository_Trust;
