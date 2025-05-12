let mkProgram = (kebab-case: {
      attrName = kebab-case;
      binName = builtins.replaceStrings ["-"] ["_"] kebab-case;
    });
in rec {
  programs = map (mkProgram) [
    "dns-arbitrary-ip"
    "dns-switcheroo"
    "dns-targeted-switcheroo"
  ];

  # Run a user-defined function for each program. Prefix each returned attrset with the attrName of
  # the program, then combine the attrsets
  each = (f:
    builtins.listToAttrs (map (program: { name = program.attrName; value = f program; }) programs)
  );
}
