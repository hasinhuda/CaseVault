package com.casevault;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.casevault", importOptions = {ImportOption.DoNotIncludeTests.class})
class ArchitectureTest {

    @ArchTest
    static final ArchRule noJavaUtilLogging = noClasses()
            .should().dependOnClassesThat().resideInAPackage("java.util.logging..")
            .as("TEST-BASE-004: Production code must not use java.util.logging directly")
            .because("CaseVault standardizes on SLF4J / Logback");
}

