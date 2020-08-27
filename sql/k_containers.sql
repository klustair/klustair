-- Table: public.k_containers

-- DROP TABLE public.k_containers;

CREATE TABLE public.k_containers
(
    name character varying COLLATE pg_catalog."default" NOT NULL,
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    namespace_uid character varying COLLATE pg_catalog."default" NOT NULL,
    pod_uid character varying COLLATE pg_catalog."default" NOT NULL,
    image character varying COLLATE pg_catalog."default",
    image_pull_policy character varying COLLATE pg_catalog."default",
    security_context json,
    init_container boolean,
    uid character varying COLLATE pg_catalog."default",
    CONSTRAINT k_containers_pkey PRIMARY KEY (name, report_uid, namespace_uid, pod_uid),
    CONSTRAINT k_containers_uid_key UNIQUE (uid),
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
        ON DELETE CASCADE
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
-- Index: k_containers_report_uid_fkey

-- DROP INDEX public.k_containers_report_uid_fkey;

CREATE INDEX k_containers_report_uid_fkey
    ON public.k_containers USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;