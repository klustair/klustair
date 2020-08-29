-- Table: public.k_container_has_images

-- DROP TABLE public.k_container_has_images;

CREATE TABLE public.k_container_has_images
(
    report_uid character varying COLLATE pg_catalog."default" NOT NULL,
    container_uid character varying COLLATE pg_catalog."default" NOT NULL,
    image_uid character varying COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT k_container_has_images_pkey PRIMARY KEY (container_uid, report_uid),
    CONSTRAINT k_container_has_images_report_uid_fkey FOREIGN KEY (report_uid)
        REFERENCES public.k_reports (uid) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
        NOT VALID
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_container_has_images
    OWNER to postgres;
-- Index: k_container_has_images_report_uid_fkey

-- DROP INDEX public.k_container_has_images_report_uid_fkey;

CREATE INDEX k_container_has_images_report_uid_fkey
    ON public.k_container_has_images USING btree
    (report_uid COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;