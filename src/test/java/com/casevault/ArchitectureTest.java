package com.casevault;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

@AnalyzeClasses(packages = "com.casevault", importOptions = {ImportOption.DoNotIncludeTests.class})
class ArchitectureTest {

    @ArchTest
    static final ArchRule noJavaUtilLogging = noClasses()
            .should().dependOnClassesThat().resideInAPackage("java.util.logging..")
            .as("TEST-BASE-004: Production code must not use java.util.logging directly")
            .because("CaseVault standardizes on SLF4J / Logback");

    @ArchTest
    static final ArchRule controllersMustNotAccessRepositories = noClasses()
            .that().resideInAPackage("..controller..")
            .should().dependOnClassesThat().resideInAPackage("..repository..")
            .as("SEC-AUTHZ-ARCH-01: Controllers must not access repositories directly")
            .because("ADR 0003 and SR-01 mandate that all data access and authorization rules must be strictly routed through service layer (CaseAccessService)");

    @ArchTest
    static final ArchRule repositoriesOnlyAccessedByServicesAndBootstrap = classes()
            .that().resideInAPackage("..repository..")
            .should().onlyBeAccessed().byAnyPackage("..repository..", "..service..", "..bootstrap..", "..config..", "..security..")
            .as("SEC-AUTHZ-ARCH-02: Repositories must only be accessed by service and security/bootstrap infrastructure")
            .because("Only services enforce tenant and role access policies");

    @ArchTest
    static final ArchRule evidenceStorageOnlyAccessedByServices = classes()
            .that().resideInAPackage("..service..")
            .and().haveNameMatching(".*(EvidenceStorageService|EvidenceStore).*")
            .should().onlyBeAccessed().byAnyPackage("..service..")
            .as("SEC-EVID-ARCH-01: Evidence storage boundary is service-only")
            .because("controllers must use CaseAccessService and never access encrypted storage directly");

    @ArchTest
    static final ArchRule evidenceRepositoryOnlyAccessedByServices = classes()
            .that().haveNameMatching(".*EvidenceRepository.*")
            .should().onlyBeAccessed().byAnyPackage("..service..")
            .as("SEC-EVID-ARCH-02: EvidenceRepository is accessed only by service classes")
            .because("all evidence queries and access policies must be strictly mediated by service layer");

    @ArchTest
    static final ArchRule controllersMustNotAccessEvidenceRepositoryOrStorage = noClasses()
            .that().resideInAPackage("..controller..")
            .should().dependOnClassesThat().haveNameMatching(".*(EvidenceRepository|EvidenceStorageService|EvidenceStore).*")
            .as("SEC-EVID-ARCH-03: Controllers must not access EvidenceRepository or storage classes directly")
            .because("controllers must strictly invoke CaseAccessService for all evidence operations");
}


