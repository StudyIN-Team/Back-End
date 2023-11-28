package studyin.global.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    INVALID_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
    EXPIRED_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "만료된 토큰 입니다."),
    UNSUPPORTED_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "지원되지 않는 토큰입니다."),
    WRONG_JWT_TOKEN(HttpStatus.UNAUTHORIZED, "잘못된 토큰입니다."),
    WRONG_VERIFI_CODE(HttpStatus.UNAUTHORIZED, "잘못된 인증 번호입니다."),
    PASSWORD_VERIFICATION_FAILED(HttpStatus.UNAUTHORIZED, "비밀번호가 일치하지 않습니다."),

    NOT_FOUND_ENTITY(HttpStatus.NOT_FOUND, "해당 데이터가 존재하지 않습니다."),
    NOT_FOUND_CHATROOM(HttpStatus.NOT_FOUND, "해당 채팅방이 존재하지 않습니다."),
    NOT_FOUND_VERIFI_CODE(HttpStatus.NOT_FOUND, "해당 이메일로 전송된 인증 번호가 존재하지 않습니다."),
    INVALID_CHATROOM_ID(HttpStatus.NOT_FOUND, "유효하지 않은 채팅방 아이디입니다."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "해당 유저가 존재하지 않습니다."),
    NOT_AUTHORIZED(HttpStatus.UNAUTHORIZED, "권한이 없습니다."),
    DUPLICATE_USERNAME(HttpStatus.CONFLICT, "이미 존재하는 아이디입니다."),
    DUPLICATE_EMAIL(HttpStatus.CONFLICT, "이미 존재하는 이메일입니다."),
    DUPLICATE_VERIFI_CODE(HttpStatus.CONFLICT, "해당 이메일로 전송된 인증 번호가 존재합니다"),
    DUPLICATED_LIKE(HttpStatus.CONFLICT, "이미 좋아요를 누른 상대입니다."),
    INVALID_NICKNAME(HttpStatus.NOT_ACCEPTABLE, "닉네임을 입력해야 합니다."),
    INVALID_GENDER(HttpStatus.NOT_ACCEPTABLE, "성별을 입력해야 합니다."),
    INVALID_IMAGE(HttpStatus.NOT_ACCEPTABLE, "이미지를 하나 이상 등록하여야 합니다."),
    INVALID_MAXIMA(HttpStatus.NOT_ACCEPTABLE, "이미지는 최대 6장까지 등록 가능합니다."),
    INVALID_AGE(HttpStatus.NOT_ACCEPTABLE, "19세 미만은 사용할 수 없습니다"),
    INVALID_ARGUMENT(HttpStatus.BAD_REQUEST, "유효하지 않은 요청값입니다."),
    INVALID_ENUM_VAL(HttpStatus.NOT_ACCEPTABLE, "유효하지 않은 열거값입니다."),
    TOKEN_REFRESH_REQUIRED(HttpStatus.NETWORK_AUTHENTICATION_REQUIRED, "새로운 토큰이 필요합니다.");
    private final HttpStatus httpStatus;
    private final String message;
}