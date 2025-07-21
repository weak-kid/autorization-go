package database

import "database/sql"

type RefreshModel struct {
	DB *sql.DB
}

type RefreshToken struct {
	Id        int    `json:"id"`
	UserGUID  string `json:"user_guid" binding:"required,uuid"`
	TokenHash string `json:"token_hash" binding:"required"`
	UserAgent string `json:"user_agent" binding:"required"`
	IpAddr    string `json:"ip_addr" binding:"required"`
}

func (repo *RefreshModel) InsertTokenRowReturningId(userGUID, hashedRefreshToken, userAgent, ipAddr string) (int, error) {
	var refreshId int
	err := repo.DB.QueryRow(`
        INSERT INTO refresh_tokens 
        (user_guid, token_hash, user_agent, ip_addr)
        VALUES ($1, $2, $3, $4)
        RETURNING id
    `, userGUID, hashedRefreshToken, userAgent, ipAddr).Scan(&refreshId)
	return refreshId, err
}

func (repo *RefreshModel) Get(id int) (*RefreshToken, error) {
	var refreshToken RefreshToken
	err := repo.DB.QueryRow(`SELECT * FROM refresh_tokens WHERE id = $1`, id).Scan(
		&refreshToken.Id,
		&refreshToken.UserGUID,
		&refreshToken.TokenHash,
		&refreshToken.UserAgent,
		&refreshToken.IpAddr,
	)
	return &refreshToken, err
}

func (repo *RefreshModel) DeleteUsersTokens(GUID string) error {
	_, err := repo.DB.Exec(`DELETE FROM refresh_tokens WHERE user_guid = $1`, GUID)
	return err
}

func (repo *RefreshModel) DeleteRefreshToken(refreshToken, GUID string) error {
	_, err := repo.DB.Exec(`DELETE FROM refresh_tokens WHERE user_guid = $1 AND token_hash = $2`, GUID, refreshToken)
	return err
}
