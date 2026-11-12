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
    static final ArchRule auditRepositoryOnlyAccessedByAuditLogService = classes()
            .that().haveSimpleName("AuditEventRepository")
            .should().onlyBeAccessed().byClassesThat().haveSimpleName("AuditLogService")
            .as("SEC-AUDIT-ARCH-01: Only AuditLogService touches the audit repository")
            .because("the audit log has exactly one append path (FR-13, SR-13)");

    @ArchTest
    static final ArchRule controllersMustNotTouchAuditRepository = noClasses()
            .that().resideInAPackage("..controller..")
            .should().dependOnClassesThat().haveSimpleName("AuditEventRepository")
            .as("SEC-AUDIT-ARCH-02: Controllers cannot touch the audit repository")
            .because("controllers must go through services");

    @ArchTest
    static final ArchRule auditRepositoryHasNoUpdateOrDeletePath = com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods()
            .that().areDeclaredInClassesThat().haveSimpleName("AuditEventRepository")
            .should().haveNameMatching("(save|count|find.*)")
            .as("SEC-AUDIT-ARCH-03: The audit repository declares no delete, remove or update method")
            .because("the audit log is append-only");

    @ArchTest
    static final ArchRule auditRepositoryIsNotACrudRepository = noClasses()
            .that().haveSimpleName("AuditEventRepository")
            .should().beAssignableTo(org.springframework.data.repository.CrudRepository.class)
            .as("SEC-AUDIT-ARCH-04: The audit repository does not inherit delete methods from CrudRepository")
            .because("CrudRepository would expose delete and deleteAll");

    @ArchTest
    static final ArchRule auditEventHasNoSetters = com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods()
            .that().areDeclaredInClassesThat().haveSimpleName("AuditEvent")
            .should().haveNameStartingWith("set")
            .as("SEC-AUDIT-ARCH-05: The audit entity is immutable and has no setters")
            .because("a stored audit row must never be modified by the application");

    @ArchTest
    static final ArchRule controllersAndSecurityUseRecorderInterfaceOnly = noClasses()
            .that().resideInAnyPackage("..controller..", "..security..", "..config..")
            .should().dependOnClassesThat().haveSimpleNameStartingWith("AuditLogService")
            .orShould().dependOnClassesThat().haveSimpleName("AuditEventRepository")
            .orShould().dependOnClassesThat().haveSimpleName("ChainedAuditEventRecorder")
            .as("SEC-AUDIT-ARCH-06: Controllers, security filters and config call AuditEventRecorder only")
            .because("only the recorder interface may be used outside the audit service layer");

    @ArchTest
    static final ArchRule auditLogServiceOnlyUsedByAuditQueryServiceAndAppendPath = classes()
            .that().haveSimpleName("AuditLogReader")
            .should().onlyBeAccessed().byClassesThat(
                    com.tngtech.archunit.core.domain.JavaClass.Predicates.simpleName("AuditQueryService")
                            .or(com.tngtech.archunit.core.domain.JavaClass.Predicates.simpleName("AuditLogService")))
            .as("SEC-AUDIT-ARCH-07: Only AuditQueryService reads the audit log (AuditLogReader); the recorder path uses the AuditAppender interface")
            .because("controllers reach the audit log only through AuditQueryService (Phase 6C); the append path is the AuditAppender interface");

    @ArchTest
    static final ArchRule controllersMustNotTouchReportRepository = noClasses()
            .that().resideInAPackage("..controller..")
            .should().dependOnClassesThat().haveSimpleName("ReportRepository")
            .as("SEC-REPORT-ARCH-01: Controllers cannot touch the report repository")
            .because("report access rules (tenant, role, state, four-eyes) live in the service layer");

    @ArchTest
    static final ArchRule reportRepositoryOnlyAccessedByServices = classes()
            .that().haveSimpleName("ReportRepository")
            .should().onlyBeAccessed().byAnyPackage("..service..")
            .as("SEC-REPORT-ARCH-02: ReportRepository is accessed only by service classes")
            .because("every report read and write must pass the report service checks");

    @ArchTest
    static final ArchRule controllersMustNotBypassReportRules = noClasses()
            .that().resideInAPackage("..controller..")
            .should().dependOnClassesThat().haveSimpleName("DefaultReportService")
            .as("SEC-REPORT-ARCH-03: Controllers use the ReportService interface, never the implementation")
            .because("the interface is the single entry point of the report workflow");

    @ArchTest
    static final ArchRule controllersMustNotAccessEvidenceRepositoryOrStorage = noClasses()
            .that().resideInAPackage("..controller..")
            .should().dependOnClassesThat().haveNameMatching(".*(EvidenceRepository|EvidenceStorageService|EvidenceStore).*")
            .as("SEC-EVID-ARCH-03: Controllers must not access EvidenceRepository or storage classes directly")
            .because("controllers must strictly invoke CaseAccessService for all evidence operations");
}


