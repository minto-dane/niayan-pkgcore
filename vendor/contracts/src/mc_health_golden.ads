-- SPDX-License-Identifier: MIT
with MC_Health_Report;
package MC_Health_Golden with SPARK_Mode, Pure is
   function Value return MC_Health_Report.Report with Global=>null;
end MC_Health_Golden;
