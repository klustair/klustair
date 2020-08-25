-- Table: public.k_reports

-- DROP TABLE public.k_reports;

CREATE TABLE public.k_reports
(
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    checktime timestamp with time zone NOT NULL,
    CONSTRAINT k_reports_pkey PRIMARY KEY (uid),
    CONSTRAINT k_reports_uid_key UNIQUE (uid)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_reports
    OWNER to postgres;

-- Table: public.k_namespaces

-- DROP TABLE public.k_namespaces;

CREATE TABLE public.k_namespaces
(
    name character varying COLLATE pg_catalog."default" NOT NULL,
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    "creationTimestamp" date NOT NULL,
    CONSTRAINT k_namespaces_pkey PRIMARY KEY (report_uid, uid),
    CONSTRAINT k_namespaces_uid_key UNIQUE (uid),
    CONSTRAINT k_namespaces_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_namespaces
    OWNER to postgres;

-- Table: public.k_pods

-- DROP TABLE public.k_pods;

CREATE TABLE public.k_pods
(
    podname character varying COLLATE pg_catalog."default" NOT NULL,
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    namespace_uid character varying COLLATE pg_catalog."default" NOT NULL,
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    "creationTimestamp" date NOT NULL,
    CONSTRAINT k_pods_pkey PRIMARY KEY (report_uid, namespace_uid, uid),
    CONSTRAINT k_pods_uid_key UNIQUE (uid),
    CONSTRAINT k_pods_namespace_uid_fkey FOREIGN KEY (namespace_uid)
        REFERENCES public.k_namespaces (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID,
    CONSTRAINT k_pods_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_pods
    OWNER to postgres;
-- Index: k_pods_namespace_uid_fkey

-- DROP INDEX public.k_pods_namespace_uid_fkey;

CREATE INDEX k_pods_namespace_uid_fkey
    ON public.k_pods USING btree
    (namespace_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;


-- Table: public.k_containers

-- DROP TABLE public.k_containers;

CREATE TABLE public.k_containers
(
    name character varying COLLATE pg_catalog."default" NOT NULL,
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    namespace_uid character varying COLLATE pg_catalog."default" NOT NULL,
    pod_uid character varying COLLATE pg_catalog."default" NOT NULL,
    image character varying COLLATE pg_catalog."default",
    "imagePullPolicy" character varying COLLATE pg_catalog."default",
    "securityContext" json,
    "initContainer" boolean,
    CONSTRAINT k_containers_pkey PRIMARY KEY (name, report_uid, namespace_uid, pod_uid),
    CONSTRAINT k_containers_namespace_uid_fkey FOREIGN KEY (namespace_uid)
        REFERENCES public.k_namespaces (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID,
    CONSTRAINT k_containers_pod_uid_fkey FOREIGN KEY (pod_uid)
        REFERENCES public.k_pods (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID,
    CONSTRAINT k_containers_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_containers
    OWNER to postgres;
-- Index: k_containers_namespace_uid_fkey

-- DROP INDEX public.k_containers_namespace_uid_fkey;

CREATE INDEX k_containers_namespace_uid_fkey
    ON public.k_containers USING btree
    (namespace_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: k_containers_pod_uid_fkey

-- DROP INDEX public.k_containers_pod_uid_fkey;

CREATE INDEX k_containers_pod_uid_fkey
    ON public.k_containers USING btree
    (pod_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;

-- Table: public.k_imageVulnSummary

-- DROP TABLE public."k_imageVulnSummary";

CREATE TABLE public."k_imageVulnSummary"
(
    image character varying COLLATE pg_catalog."default" NOT NULL,
    severity vulnerability_severities,
    total integer,
    fixed integer,
    CONSTRAINT "k_imageVulnSummary_pkey" PRIMARY KEY (image)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public."k_imageVulnSummary"
    OWNER to postgres;