-- SPDX-License-Identifier: MIT
package MC_Paths with SPARK_Mode, Pure is
   -- Lexical policy only. Kernel-side anchored, no-symlink traversal remains mandatory.
   function Safe_Component (Value : String) return Boolean
     with Global => null;
   function Safe_Relative (Value : String) return Boolean
     with Global => null;
end MC_Paths;
