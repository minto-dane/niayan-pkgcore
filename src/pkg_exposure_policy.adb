-- SPDX-License-Identifier: MIT
package body Pkg_Exposure_Policy with SPARK_Mode is
   function Evaluate (P : Policy; F : Facts) return Status is
      Limit : Counter := 0;
   begin
      if not Pkg_Advisory.Valid(F.Advisory) or else F.First_Observed_At=0 or else F.Now<F.First_Observed_At
        or else F.Advisory.Withdrawn or else F.Advisory.Known_Bad then return Blocked; end if;
      if P.Require_Fixed_Build and then not F.Fixed_Build_Available then return No_Fix_Available; end if;
      if P.Require_Recovery_Pin and then not F.Recovery_Pinned then return Blocked; end if;
      if F.Advisory.Exploited then Limit:=P.Exploited_Max_Ms;
      else case F.Advisory.Level is
         when Pkg_Advisory.Critical => Limit:=P.Critical_Max_Ms;
         when Pkg_Advisory.Important => Limit:=P.Important_Max_Ms;
         when Pkg_Advisory.Moderate => Limit:=P.Moderate_Max_Ms;
         when Pkg_Advisory.Low => Limit:=P.Low_Max_Ms;
         when Pkg_Advisory.None => return Within_Window;
      end case; end if;
      if Limit=0 then return Blocked; end if;
      if F.Now-F.First_Observed_At > Limit then return Overdue; end if;
      if F.Validation_Passed then return Due; end if;
      return Within_Window;
   end Evaluate;
end Pkg_Exposure_Policy;
