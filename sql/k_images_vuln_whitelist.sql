-- Table: public.k_images_vuln_whitelist

-- DROP TABLE public.k_images_vuln_whitelist;

CREATE TABLE public.k_images_vuln_whitelist
(
    uid uuid NOT NULL,
    vuln character varying COLLATE pg_catalog."default",
    image_uid uuid,
    message_txt text COLLATE pg_catalog."default",
    CONSTRAINT k_images_vuln_whitelist_pkey PRIMARY KEY (uid)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.k_images_vuln_whitelist
    OWNER to postgres;