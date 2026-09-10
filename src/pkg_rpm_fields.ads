-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types; with MC_Text; with Pkg_RPM;
package Pkg_RPM_Fields with SPARK_Mode, Pure is
   procedure Text(B : Bytes; M : Pkg_RPM.Metadata; Tag : Word; Item : Positive;
                  Value : out MC_Text.Value; Status : out Outcome) with Global=>null;
   procedure Number(B : Bytes; M : Pkg_RPM.Metadata; Tag : Word; Item : Positive;
                    Value : out Wide; Status : out Outcome) with Global=>null;
   function Count(M : Pkg_RPM.Metadata; Tag : Word) return Natural with Global=>null;
end Pkg_RPM_Fields;
