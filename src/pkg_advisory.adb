-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Advisory with SPARK_Mode is
   function Valid (A : Advisory) return Boolean is
     (A.ID /= Zero_Digest and then A.Package_ID /= Zero_Digest and then A.Fixed_Build /= Zero_Digest
      and then A.Metadata /= Zero_Digest and then A.Published_At > 0 and then A.Security_Epoch > 0
      and then (not A.Data_Migration or else A.Activate = Offline_Migration));
   function Decide (A : Advisory; Installed : Digest; Policy_Epoch : Counter) return Decision is
   begin
      if not Valid (A) or else Policy_Epoch > A.Security_Epoch then return Block_Installation; end if;
      if A.Withdrawn or else A.Known_Bad then return Block_Installation; end if;
      if Installed = A.Fixed_Build then return No_Action; end if;
      if A.Exploited and then A.Level >= Important then return Emergency_Change;
      elsif A.Level = Critical then return Expedite;
      elsif A.Level >= Moderate then return Schedule;
      else return No_Action; end if;
   end Decide;
end Pkg_Advisory;
