-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with MC_Store; with Pkg_Deb_Fields;
package Pkg_Deb_Metadata with SPARK_Mode => Off is
   type Observation is record
      Original, Archive, Control : Digest := Zero_Digest;
      Fields : Pkg_Deb_Fields.Document;
      Identity : Pkg_Deb_Fields.Metadata;
   end record;
   procedure Inspect (Store : in out MC_Store.Store; Original : Digest; Deadline : Counter;
                      Result : out Observation; Status : out Outcome);
   -- Rechecks original DEB -> compressed control -> raw control -> field syntax
   -- and identity and binary relationship syntax through native readers. UID 0 is refused.
   -- This is no execution grant: relationship satisfaction, source authenticity, all effects,
   -- deployment architecture support and the actual plan need independent guards.
end Pkg_Deb_Metadata;
