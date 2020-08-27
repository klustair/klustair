-- Table: public.k_images_vulnsummary

-- DROP TABLE public.k_images_vulnsummary;

CREATE TABLE public.k_images_vulnsummary
(
    uid character varying COLLATE pg_catalog."default" NOT NULL,
    severity vulnerability_severities,
    total integer,
    fixed integer,
    report_uid character varying COLLATE pg_catalog."default",
    image_uid character varying COLLATE pg_catalog."default",
    CONSTRAINT "k_imageVulnSummary_pkey" PRIMARY KEY (uid),
    CONSTRAINT k_images_vulnsummary_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_images_vulnsummary
    OWNER to postgres;
-- Index: k_images_vulnsummary_report_uid_fkey

-- DROP INDEX public.k_images_vulnsummary_report_uid_fkey;

CREATE INDEX k_images_vulnsummary_report_uid_fkey
    ON public.k_images_vulnsummary USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;