-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Faults with SPARK_Mode is
   function Valid (F : Fault) return Boolean is
     (F.Cluster_ID /= Zero_Identity and then F.Node_ID /= Zero_Identity
      and then F.Resource_ID /= Zero_Identity and then F.Boot_ID /= Zero_Identity
      and then F.Policy /= Zero_Digest and then F.Syndrome /= Zero_Digest
      and then F.Sequence > 0 and then F.Observed_At > 0
      and then F.Expires_At > F.Observed_At and then F.Occurrences > 0
      and then F.Kind /= Unknown_Domain
      and then (if F.Quality = Untrusted then F.Level <= Informational)
      and then (if F.Corrected then F.Level <= Degraded)
      and then (if F.Level >= Uncorrectable then not F.Corrected));
   function Worse (Left, Right : Severity) return Severity is
     (if Severity'Pos (Left) >= Severity'Pos (Right) then Left else Right);
   function Isolation_Required (F : Fault) return Boolean is
     (Valid (F) and then
        (F.Level >= Uncorrectable or else F.Data_At_Risk
         or else (F.Execution_At_Risk and then F.Nature /= Transient)));
   function Automatic_Disposition (F : Fault) return Disposition is
   begin
      if not Valid (F) or else F.Quality < Corroborated then
         return Escalate_Operator;
      elsif Isolation_Required (F) then
         if F.Kind in Storage | Memory | CPU | PCIe | Power | Firmware then
            return Drain_Node;
         else
            return Fence_Node;
         end if;
      elsif F.Level = Degraded then
         return Degrade_Service;
      elsif F.Level = Corrected and then F.Nature = Persistent then
         return Repair_Component;
      else
         return Observe;
      end if;
   end Automatic_Disposition;
end MC_Faults;
