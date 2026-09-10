-- SPDX-License-Identifier: BSD-3-Clause
package body MC_Health_Golden with SPARK_Mode is
   function Value return MC_Health_Report.Report is
   begin
      return (Cluster_ID=>(others=>1),Node_ID=>(others=>2),Resource_ID=>(others=>3),
         Invocation_ID=>(others=>4),Configuration=>(others=>5),Recovery_Policy=>(others=>6),
         Stamp=>(Boot_ID=>(others=>7),Sequence=>8,Observed_At=>9,Expires_At=>19),
         Result=>MC_Health_Report.Healthy,Config_Valid=>True,Dependencies_Ready=>True,
         Data_Compatible=>True,Ownership_Exclusive=>True,Business_Healthy=>True,
         Maintenance=>False,Emergency_Stop=>False);
   end;
end MC_Health_Golden;
